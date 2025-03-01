const { Router } = require("express");
const User = require("../models/user");

const router = Router();

router.get("/signin", (req, res) => {
  return res.render("signin");
});

router.get("/signup", (req, res) => {
  return res.render("signup");
});

router.get("/logout", (req, res) => {
  res.clearCookie("token").redirect("/");
});

router.post("/signin", async (req, res) => {
  const { email, inputPassword } = req.body;
  try {
    const token = await User.matchPasswordandGenerateToken(
      email,
      inputPassword
    );
    return res.cookie("token", token).redirect("/");
  } catch (error) {
    return res.render("signin", {
      error: "Incorrect Email or Password",
    });
  }
});

router.post("/signup", async (req, res) => {
  const { fullName, email, inputPassword } = req.body;
  await User.create({
    fullName,
    email,
    password: inputPassword,
  });
  return res.redirect("/user/signin");
});

module.exports = router;
