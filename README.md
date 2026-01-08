# Secure Auth API

Welcome to my learning project designed to build a robust and secure authentication system using modern Python web technologies.

## 🚀 Features

- **User Management**: Registration, user profiles, and role-based access control (User/Admin).
- **Secure Authentication**: JWT (JSON Web Tokens) for stateless authentication.
- **Password Security**: Industry-standard password hashing using Bcrypt.
- **Rate Limiting**: Protection against brute-force attacks using `slowapi`.
- **Database Integration**: Asynchronous database interaction with **SQLModel** (SQLAlchemy + Pydantic) and **PostgreSQL**.
- **Migrations**: Database schema management with **Alembic**.
- **Modern Python**: Built with **FastAPI** on **Python 3.14+**.

## 🛠️ Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/)
- **Database**: [PostgreSQL](https://www.postgresql.org/)
- **ORM**: [SQLModel](https://sqlmodel.tiangolo.com/)
- **Migrations**: [Alembic](https://alembic.sqlalchemy.org/)
- **Package Manager**: [uv](https://github.com/astral-sh/uv)

## 📋 Prerequisites

Ensure you have the following installed:

- **Python 3.14** or higher
- **uv** (Fast Python package installer and resolver)
- **PostgreSQL** (Running locally or via Docker)

## ⚙️ Setup & Installation

1. **Clone the repository**

    ```bash
    git clone <repository-url>
    cd secure_auth_api
    ```

2. **Environment Configuration**
    Create a `.env` file in the root directory. You can use the example below:

    ```env
    # .env
    PROJECT_NAME="Secure Auth API"
    API_V1_STR="/api/v1"
    
    # Security
    SECRET_KEY="your_super_secret_key_here"  # Generate a strong key!
    
    # Database
    DATABASE_URL="postgresql://user:password@localhost:5432/db_name"
    ```

3. **Install Dependencies**
    Using `uv`:

    ```bash
    uv sync
    ```

4. **Run Database Migrations**
    Initialize your database schema:

    ```bash
    uv run alembic upgrade head
    ```

## 🏃‍♂️ Running the Application

Start the development server:

```bash
uv run uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

## 📖 Documentation

FastAPI provides automatic interactive documentation. Once the app is running, visit:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## 📂 Project Structure

```
secure_auth_api/
├── app/
│   ├── api/            # Route handlers
│   ├── core/           # Config and security settings
│   ├── db/             # Database connection
│   ├── models/         # SQLModel database models
│   ├── schemas/        # Pydantic schemas for verification
│   └── main.py         # Application entry point
├── alembic/            # Migration scripts
├── pyproject.toml      # Project dependencies and settings
└── README.md           # Project documentation
```

## 🤝 Contributing

This is a learning project, but suggestions are welcome! Feel free to open an issue or submit a pull request.
