const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchUser');


const JWT_SECRET = 'mynameis$rajan';


// ROUTE 1: Create a user using : POST "/api/auth/createuser". No login required
router.post('/createuser', [
    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must contain at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {

    //if there are errors, return Bad request and the errors
    const result = validationResult(req);
    if (!result.isEmpty()) {
        return res.status(400).json({ result: result.array() });
    }

    // check whether the user with this email exists already
    try {
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json({ error: "Sorry, a user with this email already exists" })
        }

        //adding salt to password for security
        const salt = await bcrypt.genSalt(10);
        const secPass = await bcrypt.hash(req.body.password, salt)

        //create a new user
        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: secPass,
        });
        //providing authentication by generating jwt signature
        const data = {
            user: {
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWT_SECRET);


        res.json({ authToken })

    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error")
    }
})


// ROUTE2: Authenticate a user using POST "/api/auth/login". No login required
router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists(),
], async (req, res) => {

    //if there are errors, return Bad request and the errors
    const result = validationResult(req);
    if (!result.isEmpty()) {
        return res.status(400).json({ result: result.array() });
    }

    // destructuring email and password from body
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ error: "Please try to login with correct credentials" })
        }

        const passwordCompare = await bcrypt.compare(password, user.password)
        if (!passwordCompare) {
            return res.status(400).json({ error: "Please try to login with correct credentials" })
        }

        const data = {
            user: {
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWT_SECRET);
        res.json({ authToken })

    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error")
    }

})


// ROUTE3: Get loggedin User Details using POST "/api/auth/getuser". Login required
router.post('/getuser', fetchuser, async (req, res) => {

    try {
        userId = req.user.id;
        const user = await User.findById(userId).select("-password")//taking out user info from jwt signature except password
        res.send(user)
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error")
    }
})


module.exports = router