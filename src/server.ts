import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// the traditional middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());

// you probably dont want to keep these in your code as plain text
const REFRESH_TOKEN_SECRET = "refresh_secret";
const ACCESS_TOKEN_SECRET = "access_secret";

type JwtPayload = {
  email: string;
};

// ------- Login -------
app.post("/login", (req: Request, res: Response) => {
  const { email, password } = req.body;

  // validate email/username and password
  console.log(email, password, "are valid");

  // 1. generate access token and refresh token
  // 2. store refresh token in the user's cookie
  // 3. send him the access token in normal json
  // he can access the access token, but he can't access the refresh token because it's set as an httpOnly cookie
  // the server is the only one that can access the refresh token
  const accessToken = jwt.sign({ email }, ACCESS_TOKEN_SECRET);
  const refreshToken = jwt.sign({ email }, REFRESH_TOKEN_SECRET);

  res.cookie("refresh_token", refreshToken, { httpOnly: true, secure: true });

  res.json({ accessToken, refreshToken });

  // now the user can access data for some time with his access token. when it expires, he hits the /refresh endpoint
});

// ------- Refresh -------
app.post("/refresh", (req: Request, res: Response) => {
  // get the refresh token from the user's cookie
  // so the frontend doesn't have to send it in the body.
  const refreshToken = req.cookies.refresh_token;

  try {
    // validate refresh token
    const decoded = jwt.verify(
      refreshToken,
      REFRESH_TOKEN_SECRET,
    ) as JwtPayload;
    const email = decoded?.email;

    // now that we have the email, we can generate a new access token

    const newAccessToken = jwt.sign({ email }, ACCESS_TOKEN_SECRET);
    res.json({ accessToken: newAccessToken });
  } catch {
    // if the token is invalid, the frontend will redirect the user to the login page
    return res.status(401).json({ error: "invalid refresh token" });
  }

  // now the user can still navigate the website with the new access token, the only thing left
  // is to make an endpoint for the user to get his information for example /me
});

// ------- Me -------
app.get("/me", (req: Request, res: Response) => {
  // get the access token from the headers
  const authHeader = req.headers.authorization;
  const accessToken = authHeader?.split(" ")[1];

  try {
    // validate access token
    const decoded = jwt.verify(accessToken, ACCESS_TOKEN_SECRET) as JwtPayload;
    const email = decoded?.email;

    // now that we have the email, we can get the user's information
    // for example, the user's name, email, etc
    const userInfo = {
      email,
      name: "John Doe",
      age: 30,
    };

    res.json(userInfo);
  } catch {
    // if the token is invalid, the frontend will redirect the user to the login page
    return res.status(401).json({ error: "invalid access token" });
  }
});

// you can make an endpoint for the user to logout, for example save each refresh token in a database
// and delete it when the user logs out. this can add the (log out of all devices) functionality
// feel free to edit/modify this code to fit your needs or create a PR if there's something not clear or you wanna clarify
// thanks for reading all of this :)

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀  Server ready at http://localhost:${PORT}`);
});
