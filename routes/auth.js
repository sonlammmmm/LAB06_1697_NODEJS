var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');
const { CheckLogin } = require("../utils/authHandler");
const { ChangePasswordValidator, validatedResult } = require("../utils/validateHandler");

const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.pem'), 'utf8');
const publicKey  = fs.readFileSync(path.join(__dirname, '../keys/public.pem'), 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send(error.message)
    }

})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return
        }
        if (bcrypt.compareSync(password, user.password)) {
            loginCount = 0;
            await user.save()
            let token = jwt.sign({
                id: user._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            })
            res.send({ token: token })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }

})
router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})

router.post('/changepassword', CheckLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user;

        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({ message: "Mat khau cu khong chinh xac" });
        }

        await userController.UpdatePassword(user._id, newpassword);
        res.send({ message: "Doi mat khau thanh cong" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

module.exports = router;