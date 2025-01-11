const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const jwt = require('jsonwebtoken');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

app.get("/", (req, res) => {
  res.send("Welcome to the Login-Signup API!");
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(400).json({ message: "Invalid email or password" });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password" });
      }
  
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
      res.status(200).json({
        message: "Login successful!",
        token: token
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Something went wrong" });
    }
  });

const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1];
  
    if (!token) {
      return res.status(401).json({ message: "Access denied, no token provided" });
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = decoded.userId;
      next();
    } catch (error) {
      res.status(400).json({ message: "Invalid token" });
    }
  };
  
  app.get("/profile", authenticateToken, (req, res) => {
    res.status(200).json({ message: "This is a protected route" });
  });
  

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.error("Error connecting to MongoDB:", error));
