package takeover

type Fingerprint struct {
	Service    string
	CNAMEMatch []string
	BodyMatch  string
}

var Database = []Fingerprint{
	{Service: "GitHub Pages", CNAMEMatch: []string{".github.io"}, BodyMatch: "There isn't a GitHub Pages site here"},
	{Service: "Heroku", CNAMEMatch: []string{".herokuapp.com"}, BodyMatch: "No such app"},
	{Service: "AWS S3", CNAMEMatch: []string{".s3.amazonaws.com", "s3-website"}, BodyMatch: "NoSuchBucket"},
	{Service: "Azure", CNAMEMatch: []string{".azurewebsites.net", ".cloudapp.net", ".azurefd.net"}, BodyMatch: "404 Web Site not found"},
	{Service: "GitLab Pages", CNAMEMatch: []string{".gitlab.io"}, BodyMatch: "The page you're looking for could not be found"},
	{Service: "Shopify", CNAMEMatch: []string{".myshopify.com"}, BodyMatch: "Sorry, this shop is currently unavailable"},
	{Service: "WordPress.com", CNAMEMatch: []string{".wordpress.com"}, BodyMatch: "Do you want to register"},
	{Service: "Pantheon", CNAMEMatch: []string{".pantheonsite.io"}, BodyMatch: "The gods are wise, but do not know of the site which you seek."},
	{Service: "Strikingly", CNAMEMatch: []string{".strikinglydns.com"}, BodyMatch: "But if you're looking to build your own website, you've come to the right place."},
	{Service: "Surge.sh", CNAMEMatch: []string{".surge.sh"}, BodyMatch: "project not found"},
	{Service: "Bitbucket", CNAMEMatch: []string{".bitbucket.io"}, BodyMatch: "Repository not found"},
	{Service: "Zendesk", CNAMEMatch: []string{".zendesk.com"}, BodyMatch: "Help Center Closed"},
}