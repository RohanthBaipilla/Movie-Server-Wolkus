---

# Movie Hunters

Movie Hunters is a web application that allows users to manage their movie playlists. Users can sign up, create playlists, add movies, and search for movie details using the OMDB API.

## Features

- **User Authentication**: Sign up, sign in, and verify email functionality.
- **Playlist Management**: Create, update, and delete playlists.
- **Movie Management**: Add movies to playlists, delete movies from playlists.
- **Search Movies**: Search for movies using the OMDB API.
- **Public/Private Playlists**: Toggle visibility of playlists.
- **Password Reset**: Request and reset passwords via email.

## Technologies Used

- **Node.js**: Backend runtime environment.
- **Express**: Node.js framework for building the REST API.
- **MongoDB**: NoSQL database to store user and playlist information.
- **Mongoose**: MongoDB object modeling for Node.js.
- **JWT**: JSON Web Tokens for authentication.
- **Bcrypt**: Password hashing.
- **Nodemailer**: Send emails for password reset and email verification.
- **Axios**: HTTP client for making requests to the OMDB API.
- **Crypto**: Generate secure tokens for email verification and password reset.
- **dotenv**: Load environment variables from a .env file.

## Getting Started

To run this project locally, follow these steps:

### Prerequisites

1. Node.js installed on your machine.
2. MongoDB Atlas account or a local MongoDB server.

### Installation

1. Clone the repository:

   git clone https://github.com/RohanthBaipilla/Movie-Server-Wolkus.git
   cd movie-hunters

2. Install dependencies:

   npm install

3. Set up environment variables:

   Create a `.env` file in the root directory and add the following:

   PORT=5000
   mongoURI=<your_mongodb_uri>
   JWT_SECRET=your_jwt_secret
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_email_password
   apikey=your_omdb_api_key


4. Run the application:

   npm start
  

The server will start on `http://localhost:5000`.

### API Endpoints

#### Authentication

- **POST /signup**: Create a new user.
- **POST /signin**: Authenticate user and get a JWT token.
- **GET /verify-email**: Verify user's email address.
- **POST /request-reset-password**: Request password reset.
- **POST /reset-password**: Reset user's password.

#### Playlist Management

- **GET /playlists**: Get user's playlists.
- **POST /playlists**: Create a new playlist.
- **PUT /playlists/:playlistId/public**: Update playlist to public.
- **PUT /playlists/:playlistId/private**: Update playlist to private.
- **DELETE /playlists/:playlistId**: Delete a playlist.
- **GET /public/playlists/:playlistId**: Get details of a public playlist.

#### Movie Management

- **GET /search/:q**: Search movies using the OMDB API.
- **GET /movie/:imdbID**: Get details of a movie.
- **POST /playlists/:playlistId/movies**: Add a movie to a playlist.
- **DELETE /playlists/:playlistId/movies/:movieName**: Delete a movie from a playlist.

### Contributors

- Baipilla Swamy Eshwar Rohanth - [LinkedIn](https://www.linkedin.com/in/rohanthbaipilla/)

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
