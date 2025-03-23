import { useState } from 'react'
import { CardElement, useStripe, useElements } from '@stripe/react-stripe-js'
import axios from 'axios'

function PaymentForm({ onSuccess }) {
  const stripe = useStripe()
  const elements = useElements()
  const [amount, setAmount] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    if (!stripe || !elements) {
      setError('Stripe has not loaded. Please try again.')
      setLoading(false)
      return
    }
    try {
      const { data } = await axios.post(
        'http://localhost:3000/api/create-payment-intent',
        { amount },
        { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
      )
      const result = await stripe.confirmCardPayment(data.clientSecret, {
        payment_method: {
          card: elements.getElement(CardElement),
          billing_details: { name: 'Customer Name' },
        },
      })
      if (result.error) {
        setError(result.error.message)
      } else if (result.paymentIntent.status === 'succeeded') {
        alert('Payment submitted successfully! It will be confirmed shortly.')
        setAmount('')
        setTimeout(() => onSuccess(), 2000);
      } else {
        setError('Payment processing, status: ' + result.paymentIntent.status)
      }
    } catch (error) {
      setError('Payment failed: ' + (error.response?.data?.message || error.message))
      console.error('Payment error:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-white rounded shadow">
      <input
        type="number"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        placeholder="Amount in USD"
        className="w-full p-2 mb-4 border rounded"
        required
        disabled={loading}
      />
      <CardElement className="p-2 border rounded" />
      {error && <p className="text-red-500 mt-2">{error}</p>}
      <button
        type="submit"
        disabled={!stripe || loading}
        className="w-full p-2 mt-4 bg-green-500 text-white rounded disabled:opacity-50"
      >
        {loading ? 'Processing...' : 'Pay Now'}
      </button>
    </form>
  )
}

export default PaymentForm