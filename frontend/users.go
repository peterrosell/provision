package frontend

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// UserResponse returned on a successful GET, PUT, PATCH, or POST of a single user
// swagger:response
type UserResponse struct {
	// in: body
	Body *models.User
}

// UsersResponse returned on a successful GET of all the users
// swagger:response
type UsersResponse struct {
	//in: body
	Body []*models.User
}

// UserTokenResponse returned on a successful GET of user token
// swagger:response UserTokenResponse
type UserTokenResponse struct {
	//in: body
	Body models.UserToken
}

// UserBodyParameter used to inject a User
// swagger:parameters createUser putUser
type UserBodyParameter struct {
	// in: body
	// required: true
	Body *models.User
}

// UserPatchBodyParameter used to patch a User
// swagger:parameters patchUser
type UserPatchBodyParameter struct {
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

// UserPutPassword used to set the User's password
// swagger:parameters putUserPassword
type UserPutPasswordParameter struct {
	// in: body
	// required: true
	Body models.UserPassword
}

// UserPathParameter used to name a User in the path
// swagger:parameters getUser putUser patchUser deleteUser getUserToken putUserPassword headUser
type UserPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
}

// swagger:parameters getUserToken
type UserTokenQueryTTLParameter struct {
	// in: query
	TTL int `json:"ttl"`
}

// UserTokenQueryRolesParameter is used to restrict the requested
// token to a subset of the Roles that a User has.
//
// swagger:parameters getUserToken
type UserTokenQueryRolesParameter struct {
	// in: query
	Roles string `json:"roles"`
}

// UserListPathParameter used to limit lists of User by path options
// swagger:parameters listUsers listStatsUsers
type UserListPathParameter struct {
	// in: query
	Offest int `json:"offset"`
	// in: query
	Limit int `json:"limit"`
	// in: query
	Available string
	// in: query
	Valid string
	// in: query
	ReadOnly string
	// in: query
	Name string
}

// UserActionsPathParameter used to find a User / Actions in the path
// swagger:parameters getUserActions
type UserActionsPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: query
	Plugin string `json:"plugin"`
}

// UserActionPathParameter used to find a User / Action in the path
// swagger:parameters getUserAction
type UserActionPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
}

// UserActionBodyParameter used to post a User / Action in the path
// swagger:parameters postUserAction
type UserActionBodyParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
	// in: body
	// required: true
	Body map[string]interface{}
}

func (f *Frontend) InitUserApi() {
	// swagger:route GET /users Users listUsers
	//
	// Lists Users filtered by some parameters.
	//
	// This will show all Users by default.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Available = boolean
	//    Valid = boolean
	//    ReadOnly = boolean
	//
	// Functions:
	//    Eq(value) = Return items that are equal to value
	//    Lt(value) = Return items that are less than value
	//    Lte(value) = Return items that less than or equal to value
	//    Gt(value) = Return items that are greater than value
	//    Gte(value) = Return items that greater than or equal to value
	//    Between(lower,upper) = Return items that are inclusively between lower and upper
	//    Except(lower,upper) = Return items that are not inclusively between lower and upper
	//
	// Example:
	//    Name=fred - returns items named fred
	//    Name=Lt(fred) - returns items that alphabetically less than fred.
	//
	// Responses:
	//    200: UsersResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.GET("/users",
		func(c *gin.Context) {
			f.List(c, &backend.User{})
		})

	// swagger:route HEAD /users Users listStatsUsers
	//
	// Stats of the List Users filtered by some parameters.
	//
	// This will return headers with the stats of the list.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Available = boolean
	//    Valid = boolean
	//    ReadOnly = boolean
	//
	// Functions:
	//    Eq(value) = Return items that are equal to value
	//    Lt(value) = Return items that are less than value
	//    Lte(value) = Return items that less than or equal to value
	//    Gt(value) = Return items that are greater than value
	//    Gte(value) = Return items that greater than or equal to value
	//    Between(lower,upper) = Return items that are inclusively between lower and upper
	//    Except(lower,upper) = Return items that are not inclusively between lower and upper
	//
	// Example:
	//    Name=fred - returns items named fred
	//    Name=Lt(fred) - returns items that alphabetically less than fred.
	//
	// Responses:
	//    200: NoContentResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.HEAD("/users",
		func(c *gin.Context) {
			f.ListStats(c, &backend.User{})
		})

	// swagger:route POST /users Users createUser
	//
	// Create a User
	//
	// Create a User from the provided object
	//
	//     Responses:
	//       201: UserResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/users",
		func(c *gin.Context) {
			b := &backend.User{}
			f.Create(c, b)
		})

	// swagger:route GET /users/{name} Users getUser
	//
	// Get a User
	//
	// Get the User specified by {name} or return NotFound.
	//
	//     Responses:
	//       200: UserResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/users/:name",
		func(c *gin.Context) {
			f.Fetch(c, &backend.User{}, c.Param(`name`))
		})

	// swagger:route HEAD /users/{name} Users headUser
	//
	// See if a User exists
	//
	// Return 200 if the User specifiec by {name} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/users/:name",
		func(c *gin.Context) {
			f.Exists(c, &backend.User{}, c.Param(`name`))
		})

	// swagger:route GET /users/{name}/token Users getUserToken
	//
	// Get a User Token
	//
	// Get a token for the User specified by {name} or return error
	//
	//     Responses:
	//       200: UserTokenResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/users/:name/token",
		func(c *gin.Context) {
			ref := &backend.User{}
			var userName, grantorName, userSecret, grantorSecret string
			var claim *backend.DrpCustomClaims
			var err *models.Error
			wantedRoles := []string{}
			if w, h := c.GetQuery("roles"); h {
				wantedRoles = strings.Split(w, ",")
			}
			sttl, _ := c.GetQuery("ttl")
			ttl := time.Hour
			if sttl != "" {
				ttl64, err := strconv.ParseInt(sttl, 10, 64)
				if err != nil {
					res := &models.Error{
						Type:  c.Request.Method,
						Model: "users",
						Key:   c.Param(`name`),
						Code:  http.StatusBadRequest,
					}
					res.AddError(err)
					c.JSON(res.Code, res)
					return
				}
				ttl = time.Second * time.Duration(ttl64)
			}
			rt := f.rt(c, ref.Locks("get")...)
			rt.Do(func(d backend.Stores) {
				err = &models.Error{
					Type:  c.Request.Method,
					Code:  http.StatusNotFound,
					Model: "users",
					Key:   c.Param("name"),
				}
				u := rt.Find("users", c.Param("name"))
				g := rt.Find("users", f.getAuth(c).currentUser.Name)
				if u == nil || g == nil {
					err.Errorf("Not Found")
					return
				}
				uobj := backend.AsUser(u)
				gobj := backend.AsUser(g)
				userName, userSecret = uobj.Name, uobj.Secret
				grantorName, grantorSecret = gobj.Name, gobj.Secret
				claim = uobj.GenClaim(grantorName, ttl, wantedRoles...)
				err = nil
			})
			if err != nil {
				c.JSON(err.Code, err)
				return
			}
			if !f.assureSimpleAuth(c, "users", "token", userName) {
				return
			}
			claim.AddSecrets(userSecret, grantorSecret, "")

			if t, err := f.dt.SealClaims(claim); err != nil {
				ne, ok := err.(*models.Error)
				if ok {
					c.JSON(ne.Code, ne)
				} else {
					c.JSON(http.StatusBadRequest, models.NewError(c.Request.Method, http.StatusBadRequest, err.Error()))
				}
			} else {
				// Error is only if stats are not filled in.  User
				// Token should work regardless of that.
				info, _ := f.GetInfo(c)
				if info != nil {
					if a, _, e := net.SplitHostPort(c.Request.RemoteAddr); e == nil {
						info.Address = backend.LocalFor(f.l(c), net.ParseIP(a))
					}
				}
				c.JSON(http.StatusOK, models.UserToken{Token: t, Info: *info})
			}
		})

	// swagger:route PATCH /users/{name} Users patchUser
	//
	// Patch a User
	//
	// Update a User specified by {name} using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: UserResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/users/:name",
		func(c *gin.Context) {
			f.Patch(c, &backend.User{}, c.Param(`name`))
		})

	// swagger:route PUT /users/{name} Users putUser
	//
	// Put a User
	//
	// Update a User specified by {name} using a JSON User
	//
	//     Responses:
	//       200: UserResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/users/:name",
		func(c *gin.Context) {
			f.Update(c, &backend.User{}, c.Param(`name`))
		})

	// swagger:route PUT /users/{name}/password Users putUserPassword
	//
	// Set the password for a user.
	//
	// Update a User specified by {name} using a JSON User
	//
	//     Responses:
	//       200: UserResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/users/:name/password",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "users", "password", c.Param("name")) {
				return
			}
			var userPassword models.UserPassword
			if !assureDecode(c, &userPassword) {
				return
			}
			var user *models.User
			var err *models.Error
			ref := &backend.User{}
			rt := f.rt(c, ref.Locks("update")...)
			rt.Do(func(d backend.Stores) {
				res := &models.Error{
					Type:  c.Request.Method,
					Model: "users",
					Key:   c.Param(`name`),
					Code:  http.StatusNotFound,
				}
				obj := rt.Find("users", c.Param("name"))
				if obj == nil {
					res.Errorf("Not Found")
					err = res
					return
				}
				rUser := backend.AsUser(obj)
				if uErr := rUser.ChangePassword(rt, userPassword.Password); uErr != nil {
					res.Code = http.StatusBadRequest
					res.AddError(uErr)
					err = res
					return
				}
				user = models.Clone(rUser.User).(*models.User)
			})
			if err != nil {
				c.JSON(err.Code, err)
			} else {
				c.JSON(http.StatusOK, user.Sanitize())
			}
		})

	// swagger:route DELETE /users/{name} Users deleteUser
	//
	// Delete a User
	//
	// Delete a User specified by {name}
	//
	//     Responses:
	//       200: UserResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/users/:name",
		func(c *gin.Context) {
			f.Remove(c, &backend.User{}, c.Param(`name`))
		})

	user := &backend.User{}
	pActions, pAction, pRun := f.makeActionEndpoints(user.Prefix(), user, "name")

	// swagger:route GET /users/{name}/actions Users getUserActions
	//
	// List user actions User
	//
	// List User actions for a User specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionsResponse
	//       401: NoUserResponse
	//       403: NoUserResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/users/:name/actions", pActions)

	// swagger:route GET /users/{name}/actions/{cmd} Users getUserAction
	//
	// List specific action for a user User
	//
	// List specific {cmd} action for a User specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionResponse
	//       400: ErrorResponse
	//       401: NoUserResponse
	//       403: NoUserResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/users/:name/actions/:cmd", pAction)

	// swagger:route POST /users/{name}/actions/{cmd} Users postUserAction
	//
	// Call an action on the node.
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//
	//     Responses:
	//       400: ErrorResponse
	//       200: ActionPostResponse
	//       401: NoUserResponse
	//       403: NoUserResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/users/:name/actions/:cmd", pRun)
}
