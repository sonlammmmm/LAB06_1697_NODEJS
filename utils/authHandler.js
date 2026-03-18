let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.pem'), 'utf8')

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let token = req.headers.authorization.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(404).send({
                message: "ban chua dang nhap"
            })
        }

    }
}