package main

import (
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"

	"github.com/gorilla/sessions"
	"github.com/meatballhat/negroni-logrus"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/pkg/errors"
	"github.com/urfave/negroni"
)


// The session is a unique session identifier
const sessionName = "authentication"

var (
	httpAddr        = flag.String("listen", ":3000", "address:port to listen on")
	hydraAdminURL   = flag.String("HYDRA_ADMIN_URL", getHydraAdminAddress(), "hydra admin address")
	numCpu          = flag.Int("GOMAXPROCS", 0, "GOMAXPROCS number")

	certFile = flag.String("cert-file", "server.crt", " SSL certificate file")
	keyFile  = flag.String("key-file", "key.pem", "identify HTTPS client using this SSL key file")

	// This is the Hydra SDK
	client *hydra.CodeGenSDK
	// This store will be used to save user authentication
	store = sessions.NewCookieStore([]byte("something-very-secret-keep-it-safe"))
)

func getHydraAdminAddress() string {
	value := os.Getenv("HYDRA_ADMIN_URL")
	if value == "" {
		return "https://172.28.105.108:9001"
	}
	return value
}

func ConfigRuntime() {
	if *numCpu > 0 {
		runtime.GOMAXPROCS(*numCpu)
		log.Println("Running with CPUs = ", *numCpu)
	}
}

func StartGin() {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.LoadHTMLGlob("templates/*")
	router.GET("/healthz", healthzServer)
	{
		router.GET("/consent", handleConsent)
		router.POST("/consent", handleConsent)
		router.GET("/login", handleLogin)
		router.POST("/login", handleLogin)
		
		router.GET("/callback", handleCallback)
	}

	// Set up a request logger, useful for debugging
	n := negroni.New()
	n.Use(negronilogrus.NewMiddleware())
	n.UseHandler(router)

	server := &http.Server{
		Addr:    *httpAddr,
		Handler: router,
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		log.Println("receive interrupt signal")
		if err := server.Close(); err != nil {
			log.Fatal("Server Close:", err)
		}
	}()
	log.Println("Server listen on ", *httpAddr)
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		if err == http.ErrServerClosed {
			log.Println("Server closed under request")
		} else {
			log.Fatal("Server closed unexpect")
		}
	}

	log.Println("Server exist")
}

func healthzServer(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func main() {
	flag.Parse()
	ConfigRuntime()
	var err error
	// Initialize the hydra SDK. The defaults work if you started hydra as described in the README.md
	config := &hydra.Configuration{AdminURL: *hydraAdminURL,}
	client, err = hydra.NewSDK(config)
	if err != nil {
		fmt.Printf("Unable to connect to the Hydra SDK because %s", err)
		os.Exit(1)
	}
	StartGin()
}

// After pressing "click here", the Authorize Code flow is performed and the user is redirected to Hydra. Next, Hydra
// validates the consent request (it's not valid yet) and redirects us to the consent endpoint which we set with `CONSENT_URL=http://localhost:4445/consent`.
func handleConsent(c *gin.Context) {
	// Get the consent requerst id from the query.
	consentRequestID := c.Query("consent_challenge")
	if consentRequestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Consent endpoint was called without a consent request id"})
		return
	}

	// Fetch consent information
	consentRequest, response, err := client.GetConsentRequest(consentRequestID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The consent request endpoint does not respond"})
		return
	} else if response.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "Consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error()})
		return
	}

	// This helper checks if the user is already authenticated. If not, we
	// redirect them to the login endpoint.
	user := authenticated(c.Request)
	if user == "" {
		c.Redirect(http.StatusFound, "/login?login_challenge="+consentRequestID)
		return
	}

	// Apparently, the user is logged in. Now we check if we received POST
	// request, or a GET request.
	if c.Request.Method == "POST" {
		// Ok, apparently the user gave their consent!

		// Parse the HTTP form - required by Go.
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrap(err, "Could not parse form").Error()})
			return
		}

		// Let's check which scopes the user granted.
		var grantedScopes = []string{}
		for key := range c.Request.PostForm {
			// And add each scope to the list of granted scopes.
			grantedScopes = append(grantedScopes, key)
		}

		// Ok, now we accept the consent request.
		acceptConsent, response, err := client.AcceptConsentRequest(consentRequestID, swagger.AcceptConsentRequest{
			// grant_access_token_audience.
			GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,
			// The scopes our user granted.
			GrantScope: grantedScopes,
			Remember: true,
			RememberFor: 3600 ,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrap(err, "The accept consent request endpoint encountered a network error").Error()})
			return
		} else if response.StatusCode != http.StatusOK {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "Accept consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error()})
			return
		}

		// Redirect the user back to hydra, and append the consent response! If the user denies request you can
		// either handle the error in the authentication endpoint, or redirect the user back to the original application
		// with:
		//
		//   response, err := client.RejectOAuth2ConsentRequest(consentRequestId, payload)
		c.Redirect(http.StatusFound, acceptConsent.RedirectTo)
		return
	}
	if consentRequest.Skip {
		acceptConsent, response, err := client.AcceptConsentRequest(consentRequestID, swagger.AcceptConsentRequest{
			// grant_access_token_audience.
			GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,
			// The scopes our user granted.
			GrantScope: consentRequest.RequestedScope,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrap(err, "The accept consent request endpoint encountered a network error").Error()})
			return
		} else if response.StatusCode != http.StatusOK {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "Accept consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error()})
			return
		}

		// Redirect the user back to hydra, and append the consent response! If the user denies request you can
		// either handle the error in the authentication endpoint, or redirect the user back to the original application
		// with:
		//
		//   response, err := client.RejectOAuth2ConsentRequest(consentRequestId, payload)
		c.Redirect(http.StatusFound, acceptConsent.RedirectTo)
		return
	}

	// We received a get request, so let's show the html site where the user may give consent.
	c.HTML(http.StatusOK, "consent.tmpl", struct {
		*swagger.ConsentRequest
		ConsentRequestID string
	}{ConsentRequest: consentRequest, ConsentRequestID: consentRequestID})
}

// authenticated checks if our cookie store has a user stored and returns the
// user's name, or an empty string if the user is not yet authenticated.
func authenticated(r *http.Request) string {
	session, _ := store.Get(r, sessionName)
	if u, ok := session.Values["user"]; !ok {
		return ""
	} else if user, ok := u.(string); !ok {
		return ""
	} else {
		return user
	}
}

// The user hits this endpoint if not authenticated. In this example, they can sign in with the credentials
// buzz:lightyear
func handleLogin(c *gin.Context) {
	consentRequestID := c.Query("login_challenge")

	// Is it a POST request?
	if c.Request.Method == "POST" {
		username := c.PostForm("username")
		pass := c.PostForm("password")

		// TODO Check the user's credentials
		if "test" != username || "password" != pass{
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provided credentials are wrong, try test:password"})
			return
		}

		accRequest, response, err := client.AcceptLoginRequest(consentRequestID, swagger.AcceptLoginRequest{
			Subject: username,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrap(err, "The accept login request endpoint does not respond").Error()})
			return
		} else if response.StatusCode != http.StatusOK {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "Consent accept login gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error()})
            return
		}
		// Let's create a session where we store the user id. We can ignore errors from the session store
		// as it will always return a session!
		session, _ := store.Get(c.Request, sessionName)
		session.Values["user"] = fmt.Sprintf("%s-%s", username, pass)

		// Store the session in the cookie
		if err := store.Save(c.Request, c.Writer, session); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrap(err, "Could not persist cookie").Error()})
			return
		}

		// Redirect the user back to the consent endpoint. In a normal app, you would probably
		// add some logic here that is triggered when the user actually performs authentication and is not
		// part of the consent flow.
		//http.Redirect(w, r, "/consent?consent="+consentRequestID, http.StatusFound)
		http.Redirect(c.Writer, c.Request, accRequest.RedirectTo, http.StatusFound)
		return
	} // end if post

	// It's a get request, so let's render the template
	c.HTML(http.StatusOK, "login.tmpl", consentRequestID)
}

// Once the user has given their consent, we will hit this endpoint. Again,
// this is not something that would be included in a traditional consent app,
// but we added it so you can see the data once the consent flow is done.
//拿到 code后，就可以去请求token了
func handleCallback(c *gin.Context) {
	// in the real world you should check the state query parameter, but this is omitted for brevity reasons.

	// Exchange the access code for an access (and optionally) a refresh token
	code := c.Query("code")
	scope := c.Query("scope")
	state := c.Query("state")
	// Render the output
	c.HTML(http.StatusOK, "callback.tmpl", gin.H{
		"Code": code,
		"Scope": scope,
		"State": state,
	})
}