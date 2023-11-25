# flask-blog-application
A blog built with flask, the blog template created by [startbootstrap](https://github.com/StartBootstrap) and [available here](https://startbootstrap.com/theme/clean-blog) to download and modify.
## Project Capabilities Overview
* Login with your account, register for a new account.
* Create new posts (as an admin).
* Edit your posts (as an admin & being the author of the post).
* Post comments on posts you liked.
* Delete your posts.
* Logout
## Run The Application Locally
If you want to run this application locally
* Clone the repository 
```git clone https://github.com/mahmouddello/flask-blog-application```
* Want to stick with the current coding?
  * Add a secret key for ```FLASK_KEY``` and database engine url 
as ```DATABASE_URL``` as environment variables,
    for local uses I prefer using [sqlite3](https://www.sqlite.org/index.html) since it's pre-downloaded with Python,
    and the database url
should be like this e.g. : ```sqlite:///dbname.sqlite3``` or ```sqlite:///dbname.db```.

## Finally
Enjoy and have a good time. 💻🙌
