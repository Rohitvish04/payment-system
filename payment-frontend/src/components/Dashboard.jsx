import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import PaymentForm from './PaymentForm'

function Dashboard() {
  const [balance, setBalance] = useState(0)
  const [transactions, setTransactions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('') // Add error state
  const navigate = useNavigate()

  const fetchData = useCallback(async () => {
    if (loading) return;
    setLoading(true)
    setError('')
    try {
        const token = localStorage.getItem('token')
        if (!token) {
            navigate('/login')
            return
        }
        const config = { headers: { Authorization: `Bearer ${token}` } }
        const [balanceRes, transactionsRes] = await Promise.all([
            axios.get('http://localhost:3000/api/balance', config),
            axios.get('http://localhost:3000/api/transactions', config)
        ])
        console.log('Fetched transactions:', transactionsRes.data); // Debug log
        setBalance(balanceRes.data.balance)
        setTransactions(transactionsRes.data)
    } catch (error) {
        console.error('Dashboard error:', error);
        setError('Failed to load data: ' + (error.response?.data?.message || error.message))
        navigate('/login')
    } finally {
        setLoading(false)
    }
}, [navigate])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleLogout = () => {
    localStorage.removeItem('token')
    navigate('/login')
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl">Dashboard</h1>
        <button onClick={handleLogout} className="p-2 bg-red-500 text-white rounded">
          Logout
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h2 className="text-xl mb-4">Balance: ${balance}</h2>
          <PaymentForm onSuccess={fetchData} />
        </div>
        <div>
          <h2 className="text-xl mb-4">Transaction History</h2>
          <div className="bg-white p-4 rounded shadow">
            {loading ? (
              <p>Loading transactions...</p>
            ) : error ? (
              <p className="text-red-500">{error}</p>
            ) : transactions.length === 0 ? (
              <p>No transactions yet</p>
            ) : (
              transactions.map((tx) => (
                <div key={tx._id} className="border-b py-2">
                  <p>Amount: ${tx.amount}</p>
                  <p>Type: {tx.type}</p>
                  <p>Status: {tx.status}</p>
                  <p>Date: {new Date(tx.createdAt).toLocaleString()}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard