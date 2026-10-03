package fcaptcha_test

import (
	"fmt"
	"log"
	"net/http"
	"os"

	fcaptcha "github.com/WebDecoy/FCaptcha"
)

func ExampleClient_Verify() {
	client := fcaptcha.New("https://captcha.example.com", os.Getenv("FCAPTCHA_VERIFY_SECRET"))

	http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		result, err := client.Verify(r.Context(), r.FormValue(fcaptcha.TokenField), "")
		if err != nil {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
		if !result.Valid {
			http.Error(w, "verification failed: "+result.Reason, http.StatusForbidden)
			return
		}
		fmt.Fprintln(w, "thanks")
	})
}

func ExampleClient_Middleware() {
	client := fcaptcha.New("https://captcha.example.com", os.Getenv("FCAPTCHA_VERIFY_SECRET"))

	submit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, _ := fcaptcha.ResultFromContext(r.Context())
		fmt.Fprintf(w, "accepted, score %.2f\n", result.Score)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /login", client.Middleware(fcaptcha.MiddlewareOptions{Action: "login"})(submit))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
