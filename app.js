const express = require('express');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

require('dotenv').config();

const initializePassport = require('./passport-config');

initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
);

const app = express();

const users = [];

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', checkNotAuth, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
});

app.get('/login', checkAuth, (req, res) => {
    res.render('login.ejs')
});

app.post('/login', checkAuth, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/register', checkAuth, (req, res) => {
    res.render('register.ejs')
});

app.post('/register', checkAuth, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        res.redirect('/login')
    } catch {
        res.redirect('/register')
    }
});

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login')
});

function checkNotAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect('/login')
}

function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}

(() => {
    try {
        app.listen(process.env.PORT, () => console.log('App has been started...'));
    } catch (e) {
        console.log('Server Error', e.message);
        process.exit(1);
    }
})();