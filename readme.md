# Auth Service for Payment

Welcome to the **Auth Service for Payment**! 🎉 This microservice provides a robust and secure authentication system tailored specifically for payment processing applications. 

## 🚀 Features

- **User Registration**: Effortlessly register new users with secure password hashing.
- **Token Generation**: Generate access and refresh tokens to maintain user sessions seamlessly.
- **User Management**: Easily manage user information with functionalities for checking existing usernames and emails.
- **Secure**: Employs industry-standard security practices to keep user data safe.
- **gRPC Communication**: Efficient and high-performance communication using gRPC.

## 🛠️ Technologies Used

- **Golang**: A powerful programming language for building efficient and reliable applications.
- **gRPC**: A modern open-source high-performance RPC framework.
- **Bcrypt**: For secure password hashing.
- **MySQL**: A robust relational database for data storage.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/auth-service-payment.git
   cd auth-service-payment
   ```
2. Install dependencies:
    ```bash
    go mod tidy
    ```
3. Set up your environment variables in a .env file based on the provided template.
4. Run the application:
    ```bash
    go run main.go
    ```

## 🌟 Usage

This service exposes several gRPC endpoints for managing user authentication. Here's a brief overview:
- **RegisterUser**: Register a new user and receive access and refresh tokens.
- **LoginUser**: Authenticate an existing user and retrieve tokens.
- **RefreshToken**: Refresh user access tokens seamlessly.

## 🧪 Testing

To ensure code quality and functionality, unit tests are implemented using github.com/stretchr/testify. Run the tests with:
``` bash
    go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html
```

## 🤝 Contributing
We welcome contributions! Please fork the repository and submit a pull request with your changes.
1. Fork it!
2. Create your feature branch (git checkout -b feature/MyFeature)
3. Commit your changes (git commit -m 'Add some feature')
4. Push to the branch (git push origin feature/MyFeature)
5. Open a pull request

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 📫 Contact
For any inquiries or feedback, please reach out to fajaramaulanadev@gmail.com.