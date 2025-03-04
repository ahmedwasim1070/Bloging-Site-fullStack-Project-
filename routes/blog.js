const { Router } = require("express");
const multer = require("multer");
const path = require("path");

const Blog = require("../models/blogs");
const Comment = require("../models/comment");
const router = Router();

const storage = multer.diskStorage({
  destination: function (req, res, cb) {
    cb(null, path.resolve(`./public/uploads/`));
  },
  filename: function (req, file, cb) {
    const filename = `${Date.now()}-${file.originalname}`;
    cb(null, filename);
  },
});

const upload = multer({ storage });

router.get("/add-new", (req, res) => {
  return res.render("addBlog", { user: req.user });
});

router.get("/:id", async (req, res) => {
  const blog = await Blog.findById(req.params.id).populate("createdBy");
  return res.render("blog", {
    user: req.user,
    blog,
  });
});

router.post("/", upload.single("coverImage"), async (req, res) => {
  const { title, body } = req.body;
  await Blog.create({
    title,
    body,
    createdBy: req.user._id,
    coverImgURL: `/uploads/${req.file.filename}`,
  });
  return res.redirect("/");
});

router.post("/comment/:blogId", async (req, res) => {
  await Comment.create({
    content: req.body.content,
    blogId: req.params.blogId,
    createdBy: req.user._id,
  });
  return res.redirect(`/blog/${req.params.blogId}`);
});

module.exports = router;
