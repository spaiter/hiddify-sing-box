package clashapi

import (
	"io"
	"net/http"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func manageRouter(s *Server, logFactory log.Factory) http.Handler {
	r := chi.NewRouter()

	// Full config (read-only)
	r.Get("/config", getFullConfig(s))

	// Inbound CRUD
	r.Get("/inbounds", listInbounds(s))
	r.Post("/inbounds", addInbound(s))
	r.Get("/inbounds/{tag}", getInbound(s))
	r.Put("/inbounds/{tag}", updateInbound(s))
	r.Delete("/inbounds/{tag}", deleteInbound(s))

	// User CRUD
	r.Get("/inbounds/{tag}/users", listUsers(s))
	r.Post("/inbounds/{tag}/users", addUser(s))
	r.Get("/inbounds/{tag}/users/{name}", getUser(s))
	r.Put("/inbounds/{tag}/users/{name}", updateUser(s))
	r.Delete("/inbounds/{tag}/users/{name}", deleteUser(s))

	return r
}

// @Summary Get full config
// @Tags Config
// @Produce json
// @Security BearerAuth
// @Success 200 {object} option.Options
// @Failure 500 {object} HTTPError
// @Router /manage/config [get]
func getFullConfig(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		data, err := json.MarshalContext(s.ctx, options)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}

// Inbound handlers

type inboundSummary struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// @Summary List inbounds
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Success 200 {array} inboundSummary
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds [get]
func listInbounds(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		summaries := make([]inboundSummary, len(options.Inbounds))
		for i, inbound := range options.Inbounds {
			summaries[i] = inboundSummary{
				Tag:  inbound.Tag,
				Type: inbound.Type,
			}
		}
		render.JSON(w, r, summaries)
	}
}

// @Summary Get inbound by tag
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Success 200 {object} option.Inbound
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [get]
func getInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for _, inbound := range options.Inbounds {
			if inbound.Tag == tag {
				data, err := json.MarshalContext(s.ctx, inbound)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, newError(err.Error()))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
				return
			}
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// @Summary Add new inbound
// @Tags Inbounds
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param inbound body object true "Inbound config (must include type and tag)"
// @Success 201 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 409 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds [post]
func addInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var inbound option.Inbound
		err = inbound.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if inbound.Tag == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("inbound tag is required"))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for _, existing := range options.Inbounds {
				if existing.Tag == inbound.Tag {
					return options, &conflictError{Message: "inbound " + inbound.Tag + " already exists"}
				}
			}
			options.Inbounds = append(options.Inbounds, inbound)
			return options, nil
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, render.M{"message": "inbound added"})
	}
}

// @Summary Replace inbound
// @Tags Inbounds
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param inbound body object true "New inbound config"
// @Success 200 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [put]
func updateInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var inbound option.Inbound
		err = inbound.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, existing := range options.Inbounds {
				if existing.Tag == tag {
					inbound.Tag = tag
					options.Inbounds[i] = inbound
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.JSON(w, r, render.M{"message": "inbound updated"})
	}
}

// @Summary Remove inbound
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Success 204
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [delete]
func deleteInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		err := s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, inbound := range options.Inbounds {
				if inbound.Tag == tag {
					options.Inbounds = append(options.Inbounds[:i], options.Inbounds[i+1:]...)
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.NoContent(w, r)
	}
}
