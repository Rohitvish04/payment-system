import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, CardElement, useStripe, useElements } from '@stripe/react-stripe-js';
import { jsPDF } from 'jspdf';

const stripePromise = loadStripe('pk_test_51Qw7BsGC2pOWzjpmC9i4zPJ0koIk3SQOXTBgrBFXPUn5agHE249PZYe3eT1mYq19YhWx4wLuKtsSH9XpnHrzTfmL00nZVVmyJd');

function CheckoutForm({ amount, setMessage, setError }) {
  const stripe = useStripe();
  const elements = useElements();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (!stripe || !elements) {
      setError('Stripe.js has not loaded yet.');
      return;
    }

    try {
      const { data } = await axios.post('http://localhost:3000/api/create-payment-intent', 
        { amount },
        { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
      );

      const result = await stripe.confirmCardPayment(data.clientSecret, {
        payment_method: { card: elements.getElement(CardElement) }
      });

      if (result.error) {
        setError(result.error.message);
      } else if (result.paymentIntent.status === 'succeeded') {
        setMessage('Payment successful! Check your email for confirmation.');
      }
    } catch (error) {
      setError(error.response?.data?.message || 'Payment failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <CardElement />
      <button type="submit" className="mt-4 p-2 bg-green-500 text-white rounded" disabled={!stripe}>
        Pay ${amount}
      </button>
    </form>
  );
}

// In Dashboard.jsx
// In Dashboard.jsx
function ReceiptModal({ transaction, onClose }) {
  const generatePDF = () => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text('Payment Receipt', 20, 20);
    doc.setFontSize(12);
    doc.text(`Transaction ID: ${transaction.id}`, 20, 30);
    doc.text(`Amount: $${transaction.amount.toFixed(2)} ${transaction.currency.toUpperCase()}`, 20, 40);
    doc.text(`Payment Intent ID: ${transaction.paymentIntentId}`, 20, 50);
    doc.text(`Status: ${transaction.status}`, 20, 60);
    doc.text(`Date: ${new Date(transaction.createdAt).toLocaleString()}`, 20, 70);
    if (transaction.paymentMethodType) {
      doc.text(`Payment Method: ${transaction.paymentMethodType}${transaction.last4 ? ` (Ending ${transaction.last4})` : ''}`, 20, 80);
    }
    if (transaction.receiptUrl) {
      doc.text('Stripe Receipt: See online version at the link below', 20, 90);
    } else if (transaction.status === 'succeeded') {
      doc.text('Stripe Receipt: Not available at this time', 20, 90);
    }
    doc.save(`receipt_${transaction.id}.pdf`);
  };

  return (
    <div className="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-white p-8 rounded-xl shadow-2xl max-w-lg w-full mx-4">
        <h3 className="text-2xl font-semibold text-gray-800 mb-6">Payment Receipt</h3>
        
        <div className="space-y-4 text-gray-700">
          <p>
            <span className="font-medium">Transaction ID:</span> {transaction.id}
          </p>
          <p>
            <span className="font-medium">Amount:</span> ${transaction.amount.toFixed(2)} {transaction.currency.toUpperCase()}
          </p>
          <p>
            <span className="font-medium">Payment Intent ID:</span> {transaction.paymentIntentId}
          </p>
          <p>
            <span className="font-medium">Status:</span>{' '}
            <span className={`inline-block px-2 py-1 rounded text-sm ${
              transaction.status === 'succeeded' ? 'bg-green-100 text-green-700' :
              transaction.status === 'failed' ? 'bg-red-100 text-red-700' :
              'bg-yellow-100 text-yellow-700'
            }`}>
              {transaction.status}
            </span>
          </p>
          <p>
            <span className="font-medium">Date:</span> {new Date(transaction.createdAt).toLocaleString()}
          </p>
          {transaction.paymentMethodType && (
            <p>
              <span className="font-medium">Payment Method:</span>{' '}
              {transaction.paymentMethodType}{transaction.last4 ? ` (Ending ${transaction.last4})` : ''}
            </p>
          )}
          <p>
            <span className="font-medium">Stripe Receipt:</span>{' '}
            {transaction.receiptUrl ? (
              <a 
                href={transaction.receiptUrl} 
                target="_blank" 
                rel="noopener noreferrer" 
                className="text-blue-600 hover:text-blue-800 underline"
              >
                View Online
              </a>
            ) : transaction.status === 'succeeded' ? (
              <span className="text-gray-500 italic">Not available at this time</span>
            ) : (
              <span className="text-gray-500 italic">Not applicable for this status</span>
            )}
          </p>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button 
            onClick={generatePDF}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Download PDF
          </button>
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// Rest of Dashboard.jsx remains unchanged (CheckoutForm and Dashboard components)

function Dashboard() {
  const [balance, setBalance] = useState(0);
  const [amount, setAmount] = useState('');
  const [transactions, setTransactions] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [selectedTransaction, setSelectedTransaction] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('No token found');

        const [balanceRes, transactionsRes] = await Promise.all([
          axios.get('http://localhost:3000/api/balance', { headers: { Authorization: `Bearer ${token}` } }),
          axios.get('http://localhost:3000/api/transactions', { headers: { Authorization: `Bearer ${token}` } })
        ]);

        setBalance(balanceRes.data.balance / 100);
        setTransactions(transactionsRes.data);
      } catch (error) {
        console.error('Error fetching data:', error);
        navigate('/login');
      }
    };
    fetchData();
  }, [navigate]);

  const handleViewReceipt = async (transactionId) => {
    try {
      const response = await axios.get(`http://localhost:3000/api/transaction/${transactionId}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setSelectedTransaction(response.data);
    } catch (error) {
      setError(error.response?.data?.message || 'Error fetching receipt');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <div className="max-w-4xl mx-auto mt-10 p-6 bg-white rounded-lg shadow">
      <h2 className="text-2xl mb-6">Dashboard</h2>
      <p className="mb-4">Balance: ${balance.toFixed(2)}</p>
      {message && <p className="text-green-500 mb-4">{message}</p>}
      {error && <p className="text-red-500 mb-4">{error}</p>}

      <div className="mb-6">
        <h3 className="text-xl mb-2">Add Funds</h3>
        <input
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="Amount in USD"
          className="w-full p-2 mb-4 border rounded"
        />
        <Elements stripe={stripePromise}>
          <CheckoutForm amount={amount} setMessage={setMessage} setError={setError} />
        </Elements>
      </div>

      <div className="mb-6">
        <h3 className="text-xl mb-2">Transaction History</h3>
        {transactions.length === 0 ? (
          <p>No transactions yet.</p>
        ) : (
          <ul>
            {transactions.map((tx) => (
              <li key={tx._id} className="mb-2 flex justify-between items-center">
                <span>
                  ${(tx.amount / 100).toFixed(2)} - {tx.status} - {new Date(tx.createdAt).toLocaleString()}
                </span>
                <button
                  onClick={() => handleViewReceipt(tx._id)}
                  className="p-1 bg-blue-500 text-white rounded"
                >
                  View Receipt
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <button 
        onClick={handleLogout}
        className="w-full p-2 bg-red-500 text-white rounded"
      >
        Logout
      </button>

      {selectedTransaction && (
        <ReceiptModal 
          transaction={selectedTransaction} 
          onClose={() => setSelectedTransaction(null)} 
        />
      )}
    </div>
  );
}

export default Dashboard;