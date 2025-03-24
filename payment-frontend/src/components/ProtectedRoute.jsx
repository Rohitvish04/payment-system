import { useEffect } from 'react'
import { Navigate } from 'react-router-dom'
import axios from 'axios'

function ProtectedRoute({ children }) {
  const token = localStorage.getItem('token');

  useEffect(() => {
    const checkVerification = async () => {
      if (token) {
        try {
          await axios.get('http://localhost:3000/api/balance', {
            headers: { Authorization: `Bearer ${token}` }
          });
        } catch (error) {
          if (error.response?.status === 403) {
            localStorage.removeItem('token');
          }
        }
      }
    };
    checkVerification();
  }, [token]);

  return token ? children : <Navigate to="/login" />;
}

export default ProtectedRoute