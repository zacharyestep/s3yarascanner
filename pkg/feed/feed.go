package feed

import ( 
	"github.com/jinzhu/gorm"
	//sqlitedilact for gorm
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/gorilla/mux"
	"github.com/zacharyestep/s3yarascanner/pkg/models"
	"net/http"
	"text/template"
	"time"
)
//Server is s server for intelligence feeds based on the information contained in the database
type Server struct { 
	FeedDB * gorm.DB
	Router	*mux.Router
	Template	*template.Template
}

//NewServer is a factory method for FeedServer using default gorilla-mux router and the provided * db, temlpate string
func NewServer(feedTmpl string, fddb * gorm.DB) ( * Server, error) {
	tmpl, err := template.New("feed").Parse(feedTmpl)
	if err != nil { 
		return nil, err
	}
	return &Server{FeedDB: fddb, Router: mux.NewRouter(), Template: tmpl },nil
}

//NewServerTmplFile loads a new sever as above except the template arg is a filename with a template content
func NewServerTmplFile(feedTmplFile string, fddb * gorm.DB) (* Server , error) {
	tmpl, err := template.ParseFiles(feedTmplFile)
	if err != nil { 
		return nil, err
	}
	funcMap := template.FuncMap{"now":time.Now}
	tmpl = tmpl.Funcs(funcMap)
	s := &Server{FeedDB: fddb, Router: mux.NewRouter(), Template: tmpl }
	s.Routes()
	return s,nil
}

//Routes binds the routes of the configured router for the FeedServer, add additional routes here!
func (fserver * Server)  Routes() {
	fserver.Router.HandleFunc("/feed.json",fserver.handleFeeds())
}


//handleFeeds is a route-handle for feeds , returning a handler funciton
func (fserver * Server) handleFeeds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		 	models := []models.Result{}
			fserver.FeedDB.Debug().Find(models)
			fserver.Template.Execute(w,map[string]interface{}{"reports":models})
			return	
    }
}