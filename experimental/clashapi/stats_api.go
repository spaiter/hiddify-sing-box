package clashapi

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func statsRouter(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/users", getAllUserStats(s))
	r.Get("/users/{name}", getUserStats(s))
	r.Delete("/users/{name}", resetUserStats(s))
	return r
}

func getAllUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := s.userStatsManager.GetAllStats()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if stats == nil {
			stats = []UserStatsSummary{}
		}
		render.JSON(w, r, stats)
	}
}

func getUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
				days = parsed
			}
		}
		daily, err := s.userStatsManager.GetUserDaily(name, days)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if daily == nil {
			daily = []UserDailyStats{}
		}
		render.JSON(w, r, render.M{
			"user":  name,
			"daily": daily,
		})
	}
}

func resetUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		err := s.userStatsManager.ResetUser(name)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}
