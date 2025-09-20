# ES1 Backend API

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Development mode with auto-restart
npm run dev
```

## Environment Variables

Create a `.env` file:

```
PORT=2092
JWT_SECRET=your-secure-secret-key
MONGODB_URI=mongodb+srv://3alehawhaw:7HZybRRtsEm4Sge3@cluster0.tbima.mongodb.net/
FRONTEND_URL=https://euphonious-gingersnap-65d3e4.netlify.app
```

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/login` - User login
- `GET /api/schedule` - Get class schedule
- `POST /api/schedule` - Add class (auth required)
- `GET /api/subjects` - Get subjects
- `POST /api/subjects` - Create subject (auth required)
- `GET /api/homework` - Get homework
- `POST /api/homework` - Create homework (auth required)

## Default Credentials

- Admin: `admin` / `admin123`
- Teacher: `teacher` / `teacher123`
