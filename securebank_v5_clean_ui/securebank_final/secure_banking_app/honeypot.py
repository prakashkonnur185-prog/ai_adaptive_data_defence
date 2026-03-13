"""
Advanced Honeypot fake data generator.
Returns convincing but fake banking data when suspicious activity is detected.
"""

import random
import time
from datetime import datetime, timedelta


class HoneypotGenerator:
    """Generate fake but realistic banking data for suspicious sessions"""

    def __init__(self):

        # Larger fake identity pool
        self.first_names = [
            "John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert",
            "Sophia", "Daniel", "Olivia", "Matthew", "Emma", "James", "Ava"
        ]

        self.last_names = [
            "Smith", "Johnson", "Brown", "Williams", "Jones", "Garcia",
            "Miller", "Davis", "Rodriguez", "Martinez", "Patel", "Lee"
        ]

        self.fake_merchants = [
            "Amazon Marketplace",
            "Walmart Supercenter",
            "Target Store",
            "Starbucks Coffee",
            "Shell Gas Station",
            "McDonald's",
            "Best Buy Electronics",
            "Home Depot",
            "CVS Pharmacy",
            "Costco Wholesale",
            "Apple Store",
            "Uber Ride",
            "Netflix Subscription"
        ]

        self.fake_streets = [
            "Main St", "Oak Ave", "Maple Drive", "Sunset Blvd",
            "Park Lane", "River Road", "Cedar Street"
        ]

    def random_name(self):
        return f"{random.choice(self.first_names)} {random.choice(self.last_names)}"

    def generate_fake_account(self):
        """Generate fake account information"""

        balance = round(random.uniform(1000, 20000), 2)

        account = {
            'account_number': f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
            'account_type': random.choice(['Checking', 'Savings']),
            'balance': balance,
            'available_balance': round(balance - random.uniform(0, 500), 2),
            'customer_name': self.random_name(),
            'last_four_ssn': f"XXX-XX-{random.randint(1000, 9999)}",
            'email': f"user{random.randint(1000, 9999)}@mail.com",
            'phone': f"({random.randint(200, 999)}) {random.randint(200, 999)}-{random.randint(1000, 9999)}",
            'address': f"{random.randint(100, 9999)} {random.choice(self.fake_streets)}, City, ST {random.randint(10000, 99999)}"
        }

        return account

    def generate_fake_transactions(self, num_transactions=12):
        """Generate fake transaction history"""

        transactions = []
        now = datetime.now()

        for _ in range(num_transactions):

            days_ago = random.randint(0, 40)
            date = now - timedelta(days=days_ago)

            amount = round(random.uniform(5, 400), 2)

            transaction = {
                'date': date.strftime('%Y-%m-%d'),
                'description': random.choice(self.fake_merchants),
                'amount': -amount,
                'type': random.choice(['Debit', 'ATM', 'Online']),
                'status': 'Completed',
                'transaction_id': f"TXN{random.randint(100000, 999999)}"
            }

            transactions.append(transaction)

        # Add salary deposits
        for _ in range(random.randint(1, 3)):

            days_ago = random.randint(10, 30)
            date = now - timedelta(days=days_ago)

            transaction = {
                'date': date.strftime('%Y-%m-%d'),
                'description': 'Direct Deposit - Payroll',
                'amount': round(random.uniform(1500, 4000), 2),
                'type': 'Credit',
                'status': 'Completed',
                'transaction_id': f"TXN{random.randint(100000, 999999)}"
            }

            transactions.append(transaction)

        transactions.sort(key=lambda x: x['date'], reverse=True)

        return transactions

    def generate_fake_cards(self):
        """Generate fake card information"""

        cards = []

        cards.append({
            'card_type': 'Debit',
            'card_number': f"****-****-****-{random.randint(1000, 9999)}",
            'expiry': f"{random.randint(1, 12):02d}/{random.randint(26, 31)}",
            'status': 'Active',
            'daily_limit': random.choice([500, 1000, 2000, 5000])
        })

        if random.random() > 0.5:
            cards.append({
                'card_type': 'Credit',
                'card_number': f"****-****-****-{random.randint(1000, 9999)}",
                'expiry': f"{random.randint(1, 12):02d}/{random.randint(26, 31)}",
                'status': 'Active',
                'credit_limit': random.choice([5000, 10000, 15000]),
                'available_credit': random.choice([2000, 5000, 9000])
            })

        return cards

    def generate_complete_honeypot_data(self):
        """Generate complete fake banking profile"""

        # Anti-fingerprinting delay
        time.sleep(random.uniform(1.2, 2.8))

        data = {
            'account': self.generate_fake_account(),
            'transactions': self.generate_fake_transactions(15),
            'cards': self.generate_fake_cards(),
            'alerts': [
                {
                    'type': 'info',
                    'message': random.choice([
                        "Your account is secure.",
                        "Security monitoring active.",
                        "No suspicious activity detected."
                    ]),
                    'date': datetime.now().strftime('%Y-%m-%d')
                }
            ],
            'is_honeypot': True
        }

        return data


# Singleton instance
honeypot_generator = HoneypotGenerator()


def get_honeypot_data():
    """Get fake data for suspicious sessions"""
    return honeypot_generator.generate_complete_honeypot_data()


if __name__ == "__main__":

    print("Testing Honeypot Generator")
    print("="*60)

    data = get_honeypot_data()

    print("\nFake Account:")
    print(f"  Account: {data['account']['account_number']}")
    print(f"  Type: {data['account']['account_type']}")
    print(f"  Balance: ${data['account']['balance']}")
    print(f"  Name: {data['account']['customer_name']}")

    print(f"\nFake Transactions ({len(data['transactions'])}):")
    for i, txn in enumerate(data['transactions'][:5], 1):
        print(
            f"  {i}. {txn['date']} | {txn['description']} | ${txn['amount']}")

    print(f"\nFake Cards ({len(data['cards'])}):")
    for card in data['cards']:
        print(
            f"  {card['card_type']}: {card['card_number']} (Exp: {card['expiry']})")

    print(f"\nIs Honeypot: {data['is_honeypot']}")
