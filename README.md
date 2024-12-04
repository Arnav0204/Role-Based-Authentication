# Role-Based Authentication API

This is a RESTful API designed for role-based authentication and authorization, allowing users to authenticate and perform actions based on their assigned roles.

---

## Features

- User Registration and Login
- Role Assignment (e.g., Admin, User)
- JWT-based Authentication
- Protected Routes based on Roles
- Secure password storage with hashing

---

## Getting Started

### Environment Variables

Set up a `.env` file in the root directory similar to the `.env.example` file

### Insatlling Dependencies

Install all the dependencies using `go mod tidy` command in your root directory

### Start Server

Start your server on localhost usig  `go run main.go` command in your root directory

## Routes
### Registering User
`http://localhost:8080/register`
`{
  "email":"your_email",
  "password":"your_password",
  "role":"your_role"
}`

### Login User
`http://localhost:8080/login`
`{
  "email":"your_email",
  "password":"your_password"
}`

### User Permitted Route
`http://localhost:8080/userinfo`

### Admin Permitted Route
`http://localhost:8080/admininfo`
