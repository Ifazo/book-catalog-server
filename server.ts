import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt, { Secret } from "jsonwebtoken";
import dotenv from "dotenv";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const uri = process.env.MONGODB_URI as string;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

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
  const jwtToken = process.env.JWT_SECRET_TOKEN as string;
  try {
    jwt.verify(token, jwtToken);
    next();
  } catch (error) {
    return res.status(500).send("Error verifying token");
  }
};

async function run() {
  try {
    await client.connect();
    await client.db("book_catalog").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    const database = client.db("book_catalog");
    const userCollection = database.collection("users");
    const booksCollection = database.collection("books");
    const reviewsCollection = database.collection("reviews");
    const statusCollection = database.collection("status");

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const JWToken = process.env.JWT_SECRET_TOKEN as Secret;
      const token = jwt.sign(user, JWToken);
      res.send({ token });
    });

    app.post("/auth/user/create", async (req: Request, res: Response) => {
      try {
        const data = req.body;
        const { name, email, password, role } = data;
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          res.send("User already exists");
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { name, email, password: hashedPassword, role };
        console.log(user);
        const result = await userCollection.insertOne(user);
        res.status(200).send(result);
      } catch (error) {
        console.log(error);
      }
    });

    app.post("/auth/user/login", async (req: Request, res: Response) => {
      try {
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
          res.send("User does not exist");
        }
        const isPasswordCorrect = await bcrypt.compare(
          password,
          user?.password
        );
        if (!isPasswordCorrect) {
          res.send("Password is incorrect");
        }
        const payload = {
          userId: user?._id,
          email: user?.email,
          role: user?.role,
        };
        const JWTtoken = process.env.JWT_SECRET_TOKEN as Secret;
        const token = jwt.sign(payload, JWTtoken);
        res.status(200).send(token);
      } catch (error) {
        console.log(error);
      }
    });

    app.get(
      "/api/users",
      authMiddleware,
      async (_req: Request, res: Response) => {
        const users = await userCollection.find({}).toArray();
        res.send(users);
      }
    );

    app.get("/api/books", async (_req: Request, res: Response) => {
      const books = await booksCollection.find({}).toArray();
      res.send(books);
    });

    app.post(
      "/api/books",
      authMiddleware,
      async (req: Request, res: Response) => {
        try {
          const token = req.headers.authorization?.split(" ")[1];
          console.log(token);
          const decodedToken = jwt.decode(token as string);
          const { userId } = decodedToken as { userId: string };
          const book = req.body;
          book.userId = userId;
          const data = { userId: userId, ...book };
          const result = await booksCollection.insertOne(data);
          res.status(200).send(result);
        } catch (error) {
          console.log(error);
        }
      }
    );

    app.get("/api/books/:id", async (req: Request, res: Response) => {
      const id = req.params.id;
      const book = await booksCollection.findOne({ _id: new ObjectId(id) });
      res.send(book);
    });

    app.patch(
      "/api/books/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        try {
          const token = req.headers.authorization?.split(" ")[1];
          const decodedToken = jwt.decode(token as string);
          const { userId } = decodedToken as { userId: string };
          const { id } = req.params;
          const findBook = await booksCollection.findOne({
            _id: new ObjectId(id),
          });
          if (findBook?.userId !== userId) {
            return res.status(401).send("Unauthorized access");
          }
          const book = req.body;
          const result = await booksCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: book }
          );
          res.status(200).send(result);
        } catch (error) {
          console.log(error);
        }
      }
    );

    app.delete(
      "/api/books/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        const token = req.headers.authorization?.split(" ")[1];
        const decodedToken = jwt.decode(token as string);
        const { userId } = decodedToken as { userId: string };
        const { id } = req.params;
        const findBook = await booksCollection.findOne({
          _id: new ObjectId(id),
        });
        if (findBook?.userId !== userId) {
          return res.status(401).send("Unauthorized access");
        }
        const result = await booksCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      }
    );

    app.get("/api/reviews/:id", async (req: Request, res: Response) => {
      const { id } = req.params;
      const result = await reviewsCollection
        .find({ bookId: new ObjectId(id) })
        .toArray();
      res.send(result);
    });

    app.post("/api/reviews/:id", authMiddleware, async (req: Request, res: Response) => {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[ 1 ];
      const decodedToken = jwt.decode(token as string);
      const { userId } = decodedToken as { userId: string };
      const data = req.body;
      data.bookId = id;
      data.userId = userId;
      const result = await reviewsCollection.insertOne(data);
      console.log(result)
      res.send(result);
    });

    app.get("/api/status", authMiddleware, async (req: Request, res: Response) => {
      const token = req.headers.authorization?.split(" ")[ 1 ];
      const decodedToken = jwt.decode(token as string);
      const { email } = decodedToken as { email: string };
      const status = await statusCollection.find({ email }).toArray();
      res.send(status);
    });

    app.post("/api/status", authMiddleware, async (req: Request, res: Response) => {
      const token = req.headers.authorization?.split(" ")[ 1 ];
      const decodedToken = jwt.decode(token as string);
      const { email } = decodedToken as { email: string };
      const findUser = await userCollection.findOne({ email });
      if (!findUser) {
        return res.status(401).send("Unauthorized access");
      }
      const status = req.body;
      status.email = email;
      console.log(status)
      const result = await statusCollection.insertOne(status);
      res.send(result);
    });

    app.patch("/api/status/:id", authMiddleware, async (req: Request, res: Response) => {
      const id = req.params.id;
      const status = req.body;
      const result = await statusCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: status }
      );
      res.send(result);
    });

    app.delete("/api/status/:id", authMiddleware, async (req: Request, res: Response) => {
      const id = req.params.id;
      const result = await statusCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });
  } catch (error) {
    console.log(error);
  }
}
run().catch(console.dir);

app.get("/", (_req, res) => {
  res.send("Hello World!");
});

const port = 5000;
app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
