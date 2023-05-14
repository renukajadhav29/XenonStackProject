const jwt = require("jsonwebtoken");
const db = require("../routes/db-config");
const bcrypt = require("bcryptjs");

const login = async (req, res) => {
    const { email, password } = req.body;
    if(!email || !password) return res.json({ status: "error", error:"please enter your email and password"});
    else{
        db.query('select email from user where email = ?', [email], async (Err, result) => {
            if(Err) throw Err;
            if(!result[0] || !await bcrypt.compare(password, result[0],password)) return res.json({ status: "error", error: "Incorrect Email or Password" })
            else{
                const token = jwt.sign(result[0].id, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES,
                    httpOnly: true
                })

                const cookieOptions = {
                    expiresInt: new Date(Date.now() + process.env.COOKIE_EXPIRS * 24 * 60 * 60 * 1000),
                    httpOnly: true
                }
                res.cookie("userRegistered", token, cookieOptions);
                return res.json({ status: "success", success: "user has been logged In" });
            }
        })
    }
}