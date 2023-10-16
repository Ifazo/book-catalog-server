import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// const authMiddleware = (req, res, next) => {
//   const authorization = req.headers.authorization;
//   if (!authorization) {
//     return res.send({ error: true, message: "unauthorized access" });
//   }
//   const token = authorization.split(" ")[1];
//   if (!token || token === "") {
//     return res.send({ error: true, message: "unauthorized token" });
//   }
//   const jwtToken = process.env.JWT_SECRET_TOKEN;
//   jwt.verify(token, jwtToken);
//   next();
// };

app.post("/jwt", async (req, res) => {
  const user = req.body;
  const JWToken = process.env.JWT_SECRET_TOKEN;
  const token = jwt.sign(user, JWToken);
  return res.send({ token });
});

app.post("/api/auth/sign-up", async (req, res) => {
  try {
    const data = req.body;
    const { name, email, password } = data;
    const existingUser = await supabase
      .from("users")
      .select("*")
      .eq("email", email);
    if (existingUser.body.length > 0) {
      return res.send("User already exists");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { name, email, password: hashedPassword };
    const createUser = await supabase.from("users").insert(user);
    if (!createUser.body) {
      return res.send("User not created");
    }
    const payload = {
      name: user.name,
      email: user.email,
    };
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWTtoken);
    return res.send(token);
  } catch (error) {
    console.log(error.message);
  }
});

app.post("/api/auth/sign-in", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await supabase.from("users").select("*").eq("email", email);
    if (user.body.length === 0) {
      return res.send("User does not exist");
    }
    const isPasswordCorrect = await bcrypt.compare(
      password,
      user.body[0].password
    );
    if (!isPasswordCorrect) {
      return res.send("Password is incorrect");
    }
    const payload = {
      name: user.body[0].name,
      email: user.body[0].email,
    };
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWTtoken);
    return res.json(token);
  } catch (error) {
    console.log(error.message);
  }
});

app.get("/api/books", async (req, res) => {
  try {
    const search = req.query.search;
    const query = search
      ? {
          $or: [
            { title: { $regex: search, $options: "i" } },
            { author: { $regex: search, $options: "i" } },
            { genre: { $regex: search, $options: "i" } },
          ],
        }
      : {};
    const books = await supabase
      .from("books")
      .select("*")
      .ilike("title", `%${search}%`)
      .or("author", "ilike", `%${search}%`)
      .or("genre", "ilike", `%${search}%`);
    return res.send(books.body);
  } catch (error) {
    console.log(error.message);
  }
});

app.post("/api/books", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { email } = decodedToken;
    const book = req.body;
    book.email = email;
    book.createdAt = new Date();
    const result = await supabase.from("books").insert(book);
    return res.send(result.body[0]);
  } catch (error) {
    console.log(error.message);
  }
});

app.get("/api/books/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const book = await supabase.from("books").select("*").eq("id", id);
    return res.send(book.body[0]);
  } catch (error) {
    console.log(error.message);
  }
});

app.get("/api/books/user/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const books = await supabase.from("books").select("*").eq("email", email);
    return res.send(books.body);
  } catch (error) {
    console.log(error.message);
  }
});

app.patch("/api/books/:id", async (req, res) => {
  try {
    const book = req.body;
    const { id } = req.params;
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { email } = decodedToken;
    const findBook = await supabase.from("books").select("*").eq("id", id);
    if (findBook.body[0]?.email !== email) {
      return res.send("Unauthorized access");
    }
    const result = await supabase.from("books").update(book).eq("id", id);
    return res.send(result.body[0]);
  } catch (error) {
    console.log(error.message);
  }
});

app.delete("/api/books/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { email } = decodedToken;
    const findBook = await supabase.from("books").select("*").eq("id", id);
    if (findBook.body[0]?.email !== email) {
      return res.send("Unauthorized access");
    }
    const result = await supabase.from("books").delete().eq("id", id);
    return res.send(result.body[0]);
  } catch (error) {
    console.error(error.message);
  }
});

app.get("/api/reviews/:bookId", async (req, res) => {
  const { bookId } = req.params;
  const result = await supabase
    .from("reviews")
    .select("*")
    .eq("bookId", bookId);
  return res.send(result.body);
});

app.post("/api/reviews/:bookId", async (req, res) => {
  const { bookId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];
  const JWTtoken = process.env.JWT_SECRET_TOKEN;
  const decodedToken = jwt.verify(token, JWTtoken);
  const { name, email } = decodedToken;
  const data = req.body;
  data.bookId = bookId;
  data.name = name;
  data.email = email;
  const result = await supabase.from("reviews").insert(data);
  return res.send(result.body[0]);
});

app.get("/api/status/:email", async (req, res) => {
  const { email } = req.params;
  const status = await supabase.from("status").select("*").eq("email", email);
  return res.send(status.body);
});

app.post("/api/status/:bookId", async (req, res) => {
  const { bookId } = req.params;
  const token = req.headers.authorization?.split(" ")[1];
  const JWTtoken = process.env.JWT_SECRET_TOKEN;
  const decodedToken = jwt.verify(token, JWTtoken);
  const { email } = decodedToken;
  const findUser = await supabase.from("users").select("*").eq("email", email);
  if (findUser.body.length === 0) {
    return res.send("User not found");
  }
  const status = req.body;
  delete status._id;
  status.bookId = bookId;
  const result = await supabase.from("status").insert(status);
  return res.send(result.body[0]);
});

app.patch("/api/status/:id", async (req, res) => {
  const { id } = req.params;
  const status = req.body;
  const result = await supabase.from("status").update(status).eq("id", id);
  return res.send(result.body[0]);
});

app.delete("/api/status/:id", async (req, res) => {
  const { id } = req.params;
  const result = await supabase.from("status").delete().eq("id", id);
  return res.send(result.body[0]);
});

console.log("Pinged your deployment. You successfully connected to Supabase!");

app.get("/api", (_req, res) => {
  res.send("api is running successfully!");
});

app.get("/", (_req, res) => {
  res.send("React ts server is running!");
});

const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
