import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import './index.css'
import { Elements } from '@stripe/react-stripe-js'
import { loadStripe } from '@stripe/stripe-js'

const stripePromise = loadStripe('pk_test_51Qw7BsGC2pOWzjpmC9i4zPJ0koIk3SQOXTBgrBFXPUn5agHE249PZYe3eT1mYq19YhWx4wLuKtsSH9XpnHrzTfmL00nZVVmyJd'); // Replace with your Stripe publishable key

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Elements stripe={stripePromise}>
        <App />
      </Elements>
    </BrowserRouter>
  </React.StrictMode>,
)