import express, { Request, Response, NextFunction, query } from "express";
import cors from "cors";
import mongoose, { Error, Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt, { Secret } from "jsonwebtoken";
import dotenv from "dotenv";
import { ObjectId } from "mongodb";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// middleware
const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }

  const token = authorization.split(" ")[1];
  if (!token || token === "") {
    return res.status(401).send({ error: true, message: "unauthorized token" });
  }

  try {
    jwt.verify(token, process.env.JWT_ACCESS_TOKEN!);
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).send("Error verifying token");
  }
};

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI as string)
  .then(() => console.log("Connected to MongoDB"))
  .catch((error: Error) => console.error("MongoDB connection error:", error));

// Define the Book schema
const bookSchema = new Schema({
  title: { type: String, required: true },
  username: { type: String, required: true },
  email: { type: String, required: true },
  author: { type: String, required: true },
  genre: { type: String, required: true },
  date: { type: String, required: true },
  description: { type: String, required: true },
  imgUrl: { type: String, required: true },
});

interface IBook extends Document {
  title: string;
  username: string;
  email: string;
  author: string;
  genre: string;
  date: string;
  description: string;
  imgUrl: string;
}

const Book = mongoose.model<IBook>("Book", bookSchema);

// Define the User schema
const userSchema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

interface IUser extends Document {
  email: string;
  password: string;
}

const User = mongoose.model<IUser>("User", userSchema);

// Define the Review schema
const reviewSchema = new Schema({
  bookId: { type: String, required: true },
  email: { type: String, required: true },
  review: { type: String, required: true },
});

interface IReview extends Document {
  bookId: string;
  email: string;
  review: string;
}

const Review = mongoose.model<IReview>("Review", reviewSchema);

// Define the Status schema
const statusSchema = new Schema({
  bookId: { type: String, required: true },
  title: { type: String, required: true },
  author: { type: String, required: true },
  genre: { type: String, required: true },
  email: { type: String, required: true },
  status: { type: String, required: true },
});

interface IStatus extends Document {
  bookId: string;
  title: string;
  author: string;
  genre: string;
  email: string;
  status: string;
}

const Status = mongoose.model<IStatus>("Status", statusSchema);

app.post("/user/create", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.sendStatus(409);
    }
    const saltRounds = process.env.BCRYPT_SALT_ROUNDS || 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = new User({ email, password: hashedPassword });

    await user.save();
    return res.sendStatus(201);
  } catch (error) {
    console.error(error);
  }
});

app.post("/user/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404);
  }
  if (await bcrypt.compare(password, user.password)) {
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, process.env.JWT_ACCESS_TOKEN!, {
      expiresIn: "24h",
    });

    return res.json({ token });
  } else {
    return res.status(403);
  }
});

app.get("/api/books", async (req: Request, res: Response) => {
  try {
    const books = await Book.find();
    res.json(books);
  } catch (error) {
    res.status(500).json({ message: "Error while fetching books" });
  }
});

app.post("/api/books", async (req: Request, res: Response) => {
  try {
    const body = req.body;
    const book = new Book(body);
    await book.save();
    res.status(201).json(book);
  } catch (error) {
    res.status(500).json({ message: "Error while creating book" });
  }
});

app.get("/api/books/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const books = await Book.findOne({ _id: new ObjectId(id as string) });
    res.json(books);
  } catch (error) {
    res.status(500).json({ message: "Error fetching books" });
  }
});

app.get("/api/books/user/:email", async (req: Request, res: Response) => {
  const { email } = req.params;
  try {
    const books = await Book.find({ email });
    res.json(books);
  } catch (error) {
    res.status(500).json({ message: "Error fetching books" });
  }
});

app.patch("/api/books/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const updatedBookData: IBook = req.body;
    const updatedBook = await Book.findByIdAndUpdate(id, updatedBookData, {
      new: true,
    });
    res.json(updatedBook);
  } catch (error) {
    res.status(500).json({ message: "Error updating book" });
  }
});

app.delete("/api/books/:id", async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    await Book.findByIdAndDelete(id);
    res.json({ message: "Book deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting book" });
  }
});

app.get("/api/book/reviews/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const reviews = await Review.find({ bookId: id });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ message: "Error fetching reviews" });
  }
});

app.post("/api/book/reviews", async (req: Request, res: Response) => {
  const body = req.body;
  try {
    const review = new Review(body);
    await review.save();
    res.status(201).json(review);
  }
  catch (error) {
    res.status(500).json({ message: "Error while creating review" });
  }
});

app.get("/api/book/status/:email", async (req: Request, res: Response) => {
  const { email } = req.params;
  try {
    const status = await Status.find({ email });
    res.json(status);
  } catch (error) {
    res.status(500).json({ message: "Error fetching status" });
  }
});

app.post("/api/book/status", async (req: Request, res: Response) => {
  const body = req.body;
  try {
    const status = new Status(body);
    await status.save();
    res.status(201).json(status);
  } catch (error) {
    res.status(500).json({ message: "Error while creating status" });
  }
});

app.patch("/api/book/status/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const updatedStatusData: IStatus = req.body;
    const updatedStatus = await Status.findByIdAndUpdate(
      id,
      updatedStatusData,
      {
        new: true,
      }
    );
    res.json(updatedStatus);
  } catch (error) {
    res.status(500).json({ message: "Error updating status" });
  }
});

app.get("/", async (req: Request, res: Response) => {
  res.send("Book Catelog Server!");
});

app.get("/api", async (req: Request, res: Response) => {
  res.send("api is running!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
