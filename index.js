/**
 * Requirements:
 * Express for the server, modemon for dev environment, helmet for conent security policy or XSS
 */

//User enter data -> browser process data -> Server sanatize data.
const {JSDOM } = require('jsdom')
const {window } = new JSDOM('') //Required for domppurify
const DOMPurify = require('dompurify')(window) // This will sanitize user generated content
const express = require('express') //We need to install express using npm
const helmet = require('helmet') //Same domain policy
const sqlite3 = require('sqlite3').verbose(); // For implementing sql injection.
const app = express()


//Connect to database
const db = new sqlite3.Database(':memory:')

//Create user table
db.serialize(function() {
    db.run('CREATE TABLE users (id INT, name TEXT)')
    const insert = db.prepare('INSERT INTO users VALUES (?,?)')
    insert.run(1, 'LEEN ALI')
    insert.run(2, 'REEM')
    insert.run(3, 'SADEEM')
    insert.run(4, 'LYAN')
    insert.finalize()
})


//Solution number 1 for XSS making sure to accept what resources to be allowed to be loaded on the webpage.
// app.use(helmet.contentSecurityPolicy({
//     directives: {
//         defaultSrc: ["'self'"],
//         scriptSrc: ["'self'"],
//         styleSrc: ["'self'"]
//     },
// }))


app.get('/', function(req, res) {
    res.send('<h1>Hello World</h1>')
})

/////LINKS TO TEST/////
//http:localhost:3000/insecure?name=leen&lastname=bajunaid
//http://localhost:3000/insecure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>
app.get('/insecure', function(req, res) { //this is a get request
    let username = req.query.name
    let lastname = req.query.lastname
    res.send("Hi from not secure request " + username + " LastName: " + lastname)
})


//Solution 2 Santization using DOMPurify
////LINSK TO TEST/////
//http://localhost:3000/secure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>
app.get('/secure', function(req, res) {
    let username = req.query.name
    res.send("Hi from secure request " + DOMPurify.sanitize(username))
})


/**
 * SQL Injection is a different type of attack where maalicious SQL statements are inserted into input fields.
 * To protect against SQL injection, you should use parameterized queries or prepared statements when interacting
 * With database.
 */


//List users // Pretend that you are admin
////LINKS/////
//http://localhost:3000/secure/users
app.get('/secure/users', function(req, res) {
    db.all('SELECT * from users', function(err, rows) {
        if(err) {
            return res.status(500).json({error: err.message})
        }
        res.json({users: rows})
    })
})

//route to fetch data from database for a sepcific user by id
///LINKS///
//http://localhost:3000/secure/user/2
app.get('/secure/user/:id', function(req, res) {
    const userId = req.params.id
    db.get('SELECT * FROM users WHERE id = ?', [userId], function(err, row) {
        if(err) {
            return res.status(500).json({error: err.message})
        }
        if(!row) {
            return res.status(404).json({error: 'User not found'})
        }
        res.json({user: row})
    })
})

//insecure access to one of the users, passing a true sql statement as an id
// http://localhost:3000/insecure/user/1%20OR%201=1
app.get('/insecure/user/:id', function(req, res) {
    const userId = req.params.id

    const sql = "SELECT * FROM users WHERE id = " + userId
    //SELECT * FROM users WHERE id = 1 OR 1 = 1

    db.all(sql, function(err, rows){
        if(err) {
            return res.status(500).json({error: err.message})
        }
        res.json({users: rows})
    })
})

app.listen(3000, function() { //here it runs the server on a specific port number.
    console.log('Server is running at http://localhost:'+ 3000)
})