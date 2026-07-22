package clashapi

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/log"

	_ "modernc.org/sqlite"
)

type userAccumulator struct {
	upload    atomic.Int64
	download  atomic.Int64
	connCount atomic.Int64
}

type UserStatsManager struct {
	db                   *sql.DB
	logger               log.Logger
	accumulators         sync.Map // string -> *userAccumulator
	resourceAccumulators sync.Map // "user\x00resource" -> *userAccumulator
	activeConns          sync.Map // string -> *atomic.Int64
	ctx                  context.Context
	cancel               context.CancelFunc
	done                 chan struct{}
}

func newUserStatsManager(logger log.Logger, dbPath string) (*UserStatsManager, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_stats_daily (
		user       TEXT    NOT NULL,
		date       TEXT    NOT NULL,
		upload     INTEGER NOT NULL DEFAULT 0,
		download   INTEGER NOT NULL DEFAULT 0,
		conn_count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user, date)
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_resources_daily (
		user       TEXT    NOT NULL,
		date       TEXT    NOT NULL,
		resource   TEXT    NOT NULL,
		upload     INTEGER NOT NULL DEFAULT 0,
		download   INTEGER NOT NULL DEFAULT 0,
		conn_count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user, date, resource)
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &UserStatsManager{
		db:     db,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}, nil
}

func (m *UserStatsManager) Start() {
	go m.flushLoop()
}

func (m *UserStatsManager) Close() error {
	m.cancel()
	<-m.done
	m.flush()
	return m.db.Close()
}

func (m *UserStatsManager) flushLoop() {
	defer close(m.done)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.flush()
		}
	}
}

func (m *UserStatsManager) getAccumulator(user string) *userAccumulator {
	v, _ := m.accumulators.LoadOrStore(user, &userAccumulator{})
	return v.(*userAccumulator)
}

func resourceKey(user, resource string) string {
	return user + "\x00" + resource
}

func parseResourceKey(key string) (user, resource string) {
	i := strings.IndexByte(key, 0)
	if i < 0 {
		return key, ""
	}
	return key[:i], key[i+1:]
}

func (m *UserStatsManager) getResourceAccumulator(user, resource string) *userAccumulator {
	v, _ := m.resourceAccumulators.LoadOrStore(resourceKey(user, resource), &userAccumulator{})
	return v.(*userAccumulator)
}

func (m *UserStatsManager) PushUploaded(user string, resource string, n int64) {
	m.getAccumulator(user).upload.Add(n)
	if resource != "" {
		m.getResourceAccumulator(user, resource).upload.Add(n)
	}
}

func (m *UserStatsManager) PushDownloaded(user string, resource string, n int64) {
	m.getAccumulator(user).download.Add(n)
	if resource != "" {
		m.getResourceAccumulator(user, resource).download.Add(n)
	}
}

func (m *UserStatsManager) ConnectionOpened(user string, resource string) {
	m.getAccumulator(user).connCount.Add(1)
	v, _ := m.activeConns.LoadOrStore(user, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
	if resource != "" {
		m.getResourceAccumulator(user, resource).connCount.Add(1)
	}
}

func (m *UserStatsManager) ConnectionClosed(user string) {
	v, ok := m.activeConns.Load(user)
	if ok {
		v.(*atomic.Int64).Add(-1)
	}
}

func (m *UserStatsManager) flush() {
	today := time.Now().UTC().Format("2006-01-02")
	tx, err := m.db.Begin()
	if err != nil {
		m.logger.Error("user stats flush begin tx: ", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO user_stats_daily (user, date, upload, download, conn_count)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user, date) DO UPDATE SET
			upload = upload + excluded.upload,
			download = download + excluded.download,
			conn_count = conn_count + excluded.conn_count`)
	if err != nil {
		m.logger.Error("user stats flush prepare: ", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	m.accumulators.Range(func(key, value any) bool {
		user := key.(string)
		acc := value.(*userAccumulator)
		up := acc.upload.Swap(0)
		down := acc.download.Swap(0)
		conns := acc.connCount.Swap(0)
		if up == 0 && down == 0 && conns == 0 {
			return true
		}
		_, err := stmt.Exec(user, today, up, down, conns)
		if err != nil {
			m.logger.Error("user stats flush exec for ", user, ": ", err)
		}
		return true
	})

	resStmt, err := tx.Prepare(`INSERT INTO user_resources_daily (user, date, resource, upload, download, conn_count)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(user, date, resource) DO UPDATE SET
			upload = upload + excluded.upload,
			download = download + excluded.download,
			conn_count = conn_count + excluded.conn_count`)
	if err != nil {
		m.logger.Error("user resource stats flush prepare: ", err)
		tx.Commit()
		return
	}
	defer resStmt.Close()

	m.resourceAccumulators.Range(func(key, value any) bool {
		compositeKey := key.(string)
		acc := value.(*userAccumulator)
		up := acc.upload.Swap(0)
		down := acc.download.Swap(0)
		conns := acc.connCount.Swap(0)
		if up == 0 && down == 0 && conns == 0 {
			return true
		}
		user, resource := parseResourceKey(compositeKey)
		_, err := resStmt.Exec(user, today, resource, up, down, conns)
		if err != nil {
			m.logger.Error("user resource stats flush exec for ", user, "/", resource, ": ", err)
		}
		return true
	})

	if err := tx.Commit(); err != nil {
		m.logger.Error("user stats flush commit: ", err)
	}
}

type UserStatsSummary struct {
	User      string `json:"user"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	ConnCount int64  `json:"conn_count"`
	Active    int64  `json:"active"`
}

type UserDailyStats struct {
	Date      string `json:"date"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	ConnCount int64  `json:"conn_count"`
}

type UserResourceStats struct {
	Resource  string `json:"resource"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	ConnCount int64  `json:"conn_count"`
}

func (m *UserStatsManager) GetAllStats() ([]UserStatsSummary, error) {
	rows, err := m.db.Query(`SELECT user, SUM(upload), SUM(download), SUM(conn_count)
		FROM user_stats_daily GROUP BY user ORDER BY user`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	statsMap := make(map[string]*UserStatsSummary)
	var order []string
	for rows.Next() {
		var s UserStatsSummary
		if err := rows.Scan(&s.User, &s.Upload, &s.Download, &s.ConnCount); err != nil {
			return nil, err
		}
		statsMap[s.User] = &s
		order = append(order, s.User)
	}

	// Add unflushed in-memory deltas
	m.accumulators.Range(func(key, value any) bool {
		user := key.(string)
		acc := value.(*userAccumulator)
		s, ok := statsMap[user]
		if !ok {
			s = &UserStatsSummary{User: user}
			statsMap[user] = s
			order = append(order, user)
		}
		s.Upload += acc.upload.Load()
		s.Download += acc.download.Load()
		s.ConnCount += acc.connCount.Load()
		return true
	})

	// Add active connection counts
	m.activeConns.Range(func(key, value any) bool {
		user := key.(string)
		if s, ok := statsMap[user]; ok {
			s.Active = value.(*atomic.Int64).Load()
			if s.Active < 0 {
				s.Active = 0
			}
		}
		return true
	})

	result := make([]UserStatsSummary, 0, len(order))
	for _, user := range order {
		result = append(result, *statsMap[user])
	}
	return result, nil
}

func (m *UserStatsManager) GetUserDaily(user string, days int) ([]UserDailyStats, error) {
	rows, err := m.db.Query(`SELECT date, upload, download, conn_count
		FROM user_stats_daily WHERE user = ? ORDER BY date DESC LIMIT ?`, user, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserDailyStats
	for rows.Next() {
		var d UserDailyStats
		if err := rows.Scan(&d.Date, &d.Upload, &d.Download, &d.ConnCount); err != nil {
			return nil, err
		}
		result = append(result, d)
	}

	// Add today's unflushed data
	today := time.Now().UTC().Format("2006-01-02")
	if acc, ok := m.accumulators.Load(user); ok {
		a := acc.(*userAccumulator)
		up := a.upload.Load()
		down := a.download.Load()
		conns := a.connCount.Load()
		if up > 0 || down > 0 || conns > 0 {
			if len(result) > 0 && result[0].Date == today {
				result[0].Upload += up
				result[0].Download += down
				result[0].ConnCount += conns
			} else {
				result = append([]UserDailyStats{{Date: today, Upload: up, Download: down, ConnCount: conns}}, result...)
			}
		}
	}
	return result, nil
}

func (m *UserStatsManager) GetUserResources(user string, days int) ([]UserResourceStats, error) {
	rows, err := m.db.Query(`SELECT resource, SUM(upload), SUM(download), SUM(conn_count)
		FROM user_resources_daily
		WHERE user = ? AND date >= date('now', '-' || ? || ' days')
		GROUP BY resource
		ORDER BY SUM(upload) + SUM(download) DESC`, user, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	statsMap := make(map[string]*UserResourceStats)
	var order []string
	for rows.Next() {
		var s UserResourceStats
		if err := rows.Scan(&s.Resource, &s.Upload, &s.Download, &s.ConnCount); err != nil {
			return nil, err
		}
		statsMap[s.Resource] = &s
		order = append(order, s.Resource)
	}

	// Add unflushed in-memory deltas for this user
	prefix := user + "\x00"
	m.resourceAccumulators.Range(func(key, value any) bool {
		compositeKey := key.(string)
		if !strings.HasPrefix(compositeKey, prefix) {
			return true
		}
		_, resource := parseResourceKey(compositeKey)
		acc := value.(*userAccumulator)
		up := acc.upload.Load()
		down := acc.download.Load()
		conns := acc.connCount.Load()
		if up == 0 && down == 0 && conns == 0 {
			return true
		}
		s, ok := statsMap[resource]
		if !ok {
			s = &UserResourceStats{Resource: resource}
			statsMap[resource] = s
			order = append(order, resource)
		}
		s.Upload += up
		s.Download += down
		s.ConnCount += conns
		return true
	})

	result := make([]UserResourceStats, 0, len(order))
	for _, res := range order {
		result = append(result, *statsMap[res])
	}
	return result, nil
}

func (m *UserStatsManager) ResetUser(user string) error {
	_, err := m.db.Exec(`DELETE FROM user_stats_daily WHERE user = ?`, user)
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`DELETE FROM user_resources_daily WHERE user = ?`, user)
	if err != nil {
		return err
	}
	if acc, ok := m.accumulators.Load(user); ok {
		a := acc.(*userAccumulator)
		a.upload.Store(0)
		a.download.Store(0)
		a.connCount.Store(0)
	}
	prefix := user + "\x00"
	m.resourceAccumulators.Range(func(key, value any) bool {
		if strings.HasPrefix(key.(string), prefix) {
			m.resourceAccumulators.Delete(key)
		}
		return true
	})
	return nil
}

func (m *UserStatsManager) ResetAll() error {
	_, err := m.db.Exec(`DELETE FROM user_stats_daily`)
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`DELETE FROM user_resources_daily`)
	if err != nil {
		return err
	}
	m.accumulators.Range(func(key, value any) bool {
		m.accumulators.Delete(key)
		return true
	})
	m.resourceAccumulators.Range(func(key, value any) bool {
		m.resourceAccumulators.Delete(key)
		return true
	})
	return nil
}
