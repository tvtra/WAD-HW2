1. In the basic part, I used session to implement authentication feature. The session information is stored in 'sessions' database with 2 keys: sessionid and email. If the browser with no valid sessionid go to the /profile, it will redirect into /, where is the login form. If user provide valid credentials, it will generate a new valid sessionid, set it to cookie, store it into database and redirect user to /profile. User's credentials and other information are stored in 'users' database.
2. In the advanced part, I did the following things:
- In the bottom of login form, I put an a tag, which links to /signup. To create new account, user need to provide email and password. If email already taken, an error will show up. The password is hashed before store into the database using bcrypt library. 
- For logout feature, I created a button in profile page. When user click to that button, the sessionid in 'sessions' database will be deleted, and user will be redirected to /.
- I also created a button for password change feature, which links to password change form. To change password, user need to provide correct password and enter new password twice.
- Every user has a default avatar. For changing the avatar feature, I created a input file type and a button to submit uploaded file. The allowed extesions are png, jpg, jpeg. After file uploaded, the filename field in users database will change to new filename.
- Profile page has some field like firstname, lastname. A button was created to submit profile change.