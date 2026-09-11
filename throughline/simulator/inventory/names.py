"""Fictional-but-realistic vocabularies: people names, job titles, locations, service words."""
from __future__ import annotations

FIRST_NAMES: list[str] = [
    "Aaliyah", "Aaron", "Abigail", "Adaeze", "Adam", "Aditi", "Adrian", "Ahmed", "Aisha", "Akira", "Alejandro", "Alex",
    "Alicia", "Amara", "Amelia", "Amir", "Ana", "Andre", "Andrea", "Angela", "Anika", "Anthony", "Antoine", "Arjun",
    "Asha", "Ashley", "Ava", "Ayodele", "Beatriz", "Benjamin", "Bianca", "Blake", "Brandon", "Brianna", "Caleb", "Camila",
    "Carlos", "Carmen", "Caroline", "Cassandra", "Catherine", "Cedric", "Chloe", "Chinwe", "Christopher", "Claire",
    "Colin", "Connor", "Daniel", "Daniela", "Darius", "David", "Deepa", "Derek", "Desmond", "Devon", "Diego", "Dmitri",
    "Dominic", "Eleanor", "Elena", "Eli", "Elijah", "Elise", "Emeka", "Emily", "Emma", "Eric", "Erin", "Esther", "Ethan",
    "Eva", "Evelyn", "Fatima", "Felix", "Fernanda", "Fiona", "Francesca", "Gabriel", "Gabriela", "Gavin", "Grace", "Hana",
    "Hannah", "Harper", "Hassan", "Helena", "Henry", "Hiroshi", "Ibrahim", "Ingrid", "Isaac", "Isabella", "Ivan", "Jack",
    "Jacob", "Jade", "Jamal", "James", "Jasmine", "Jason", "Javier", "Jenna", "Jeremy", "Jessica", "Jonah", "Jordan",
    "Joseph", "Joshua", "Julia", "Julian", "Justin", "Kaitlyn", "Kamal", "Karen", "Katherine", "Kavya", "Keiko", "Kenji",
    "Kevin", "Khalid", "Kiara", "Kofi", "Kwame", "Laila", "Lauren", "Leah", "Leila", "Leon", "Leonardo", "Liam", "Lila",
    "Lucas", "Lucia", "Luis", "Luke", "Madison", "Malik", "Manuel", "Marco", "Margaret", "Maria", "Mariam", "Mark",
    "Martin", "Mateo", "Matthew", "Maya", "Mei", "Michael", "Michelle", "Miguel", "Mila", "Mohammed", "Monica", "Nadia",
    "Naomi", "Natalie", "Nathan", "Neha", "Nicholas", "Nicole", "Nina", "Noah", "Nora", "Ojas", "Olivia", "Omar", "Oscar",
    "Owen", "Pablo", "Patrick", "Paula", "Peter", "Philip", "Quentin", "Rachel", "Rafael", "Rahul", "Raj", "Ravi",
    "Rebecca", "Renata", "Rhea", "Ricardo", "Riley", "Rohan", "Rosa", "Ruby", "Ryan", "Sabrina", "Sadie", "Samuel",
    "Sandra", "Sanjay", "Sara", "Sarah", "Sasha", "Sean", "Sebastian", "Selin", "Seth", "Shreya", "Simon", "Sofia",
    "Sophie", "Stella", "Stephen", "Tamara", "Tariq", "Tatiana", "Theo", "Thomas", "Tobias", "Tomas", "Tyler", "Uma",
    "Valentina", "Vanessa", "Victor", "Victoria", "Vikram", "Vivian", "Wei", "William", "Ximena", "Yara", "Yasmin",
    "Yuki", "Yusuf", "Zachary", "Zainab", "Zoe",
]

LAST_NAMES: list[str] = [
    "Abernathy", "Acosta", "Adebayo", "Adler", "Aguilar", "Ahmadi", "Alvarez", "Anand", "Andersen", "Antonelli",
    "Arellano", "Armstrong", "Ashford", "Atkinson", "Bader", "Bailey", "Banerjee", "Barlow", "Barnes", "Bautista",
    "Becker", "Bennett", "Bergstrom", "Bhatt", "Blackwood", "Blanchard", "Bowen", "Brennan", "Brooks", "Burke",
    "Caldwell", "Callahan", "Campos", "Cardenas", "Carmichael", "Carvalho", "Castellano", "Chandra", "Chaudhry",
    "Chen", "Cho", "Choudhury", "Clarke", "Cohen", "Coleman", "Connolly", "Cortez", "Crawford", "Cunningham", "Dalton",
    "Das", "Delgado", "Desai", "Dias", "Dixon", "Donovan", "Doyle", "Duarte", "Dubois", "Duncan", "Eastwood", "Ellis",
    "Emerson", "Escobar", "Espinoza", "Esposito", "Fairbanks", "Farrell", "Ferreira", "Fischer", "Fitzgerald",
    "Fleming", "Flores", "Foster", "Fournier", "Franklin", "Fuentes", "Gallagher", "Garza", "Gill", "Goldberg",
    "Gonzalez", "Goodwin", "Graham", "Greenwood", "Grimaldi", "Gupta", "Gutierrez", "Haddad", "Hale", "Hamilton",
    "Hansen", "Harrington", "Hartley", "Hayashi", "Henderson", "Hernandez", "Higgins", "Hoffman", "Holloway", "Huang",
    "Hughes", "Ibarra", "Ingram", "Iqbal", "Iyer", "Jacobs", "Jansen", "Jarvis", "Jensen", "Jimenez", "Joshi", "Kaplan",
    "Kapoor", "Kaur", "Keller", "Kennedy", "Khan", "Kim", "Kowalski", "Krishnan", "Kumar", "Lambert", "Larsen", "Laurent",
    "Lawson", "Lee", "Lindqvist", "Liu", "Lopez", "Lowe", "Lucas", "Lynch", "Macdonald", "Maddox", "Mahoney", "Malhotra",
    "Marchetti", "Marsh", "Martinez", "Matsuda", "McCarthy", "Mehta", "Mendoza", "Mercer", "Meyer", "Mitchell", "Molina",
    "Monroe", "Montgomery", "Moreau", "Moreno", "Morrison", "Mukherjee", "Murphy", "Nakamura", "Navarro", "Nguyen",
    "Nielsen", "Novak", "Nwosu", "O'Brien", "O'Connor", "Ochoa", "Okafor", "Okonkwo", "Oliveira", "Olsen", "Ortega",
    "Osei", "Owens", "Padilla", "Palmer", "Park", "Patel", "Pearson", "Pereira", "Petrov", "Pham", "Pierce", "Prescott",
    "Quinn", "Rahman", "Ramirez", "Ramos", "Rao", "Reddy", "Reyes", "Richter", "Rivera", "Roberts", "Rodriguez",
    "Romero", "Rossi", "Rowe", "Russo", "Saito", "Salazar", "Sandoval", "Santos", "Sato", "Schmidt", "Schneider", "Sharma",
    "Shaw", "Silva", "Simmons", "Singh", "Sokolov", "Sorensen", "Sousa", "Spencer", "Stewart", "Sullivan", "Sutton",
    "Takahashi", "Tanaka", "Thornton", "Torres", "Tran", "Underwood", "Vance", "Varga", "Vargas", "Vasquez", "Vega",
    "Venkataraman", "Villanueva", "Vogel", "Wagner", "Walsh", "Wang", "Watanabe", "Weber", "Whitaker", "Wilkins",
    "Williams", "Wolfe", "Wright", "Wu", "Xu", "Yamamoto", "Yilmaz", "Yoon", "Young", "Zhang", "Zhao", "Zimmerman",
]

# department -> weighted titles (weight is relative frequency)
TITLES: dict[str, list[tuple[str, int]]] = {
    "Engineering": [
        ("Software Engineer", 30), ("Senior Software Engineer", 25), ("Staff Software Engineer", 6),
        ("Principal Engineer", 2), ("Engineering Manager", 5), ("Site Reliability Engineer", 6),
        ("Platform Engineer", 6), ("DevOps Engineer", 4), ("Data Engineer", 5), ("Machine Learning Engineer", 4),
        ("Security Engineer", 3), ("QA Automation Engineer", 4), ("Mobile Engineer", 4), ("Technical Program Manager", 3),
        ("Product Manager", 4), ("Engineering Intern", 2),
    ],
    "Operations": [
        ("IT Support Specialist", 12), ("IT Systems Administrator", 6), ("Network Engineer", 4),
        ("Payment Operations Analyst", 14), ("Senior Payment Operations Analyst", 6), ("Fraud Analyst", 10),
        ("Senior Fraud Investigator", 4), ("Operations Manager", 4), ("Business Analyst", 6), ("Service Desk Lead", 2),
        ("Endpoint Administrator", 2), ("Reconciliation Specialist", 6),
    ],
    "Finance": [
        ("Financial Analyst", 10), ("Senior Financial Analyst", 6), ("Treasury Operations Analyst", 6),
        ("Senior Accountant", 6), ("Staff Accountant", 6), ("FP&A Manager", 2), ("Controller", 1),
        ("Accounts Payable Specialist", 4), ("Treasury Manager", 1), ("Revenue Accountant", 3),
    ],
    "Sales & Marketing": [
        ("Account Executive", 12), ("Sales Development Representative", 10), ("Partnerships Manager", 4),
        ("Marketing Manager", 4), ("Content Strategist", 3), ("Growth Marketing Lead", 2), ("Demand Generation Specialist", 4),
        ("Solutions Consultant", 5), ("Brand Designer", 2), ("Sales Operations Analyst", 3),
    ],
    "Compliance & Risk": [
        ("Compliance Analyst", 10), ("Senior Compliance Analyst", 5), ("AML Investigator", 8), ("Risk Analyst", 6),
        ("Risk Manager", 2), ("Regulatory Affairs Specialist", 3), ("BSA Officer", 1), ("Third-Party Risk Analyst", 3),
        ("Internal Auditor", 3),
    ],
    "Support": [
        ("Customer Support Specialist", 30), ("Senior Customer Support Specialist", 10), ("Technical Support Engineer", 8),
        ("Support Team Lead", 4), ("Support Quality Analyst", 3), ("Knowledge Base Writer", 2), ("Escalations Specialist", 4),
    ],
    "Executive": [
        ("Executive Assistant", 6), ("Chief of Staff", 1), ("General Counsel", 1), ("Corporate Counsel", 3),
        ("HR Business Partner", 5), ("Talent Acquisition Partner", 5), ("People Operations Specialist", 4),
        ("Office Manager", 2), ("Vice President", 4), ("Senior Director", 4),
    ],
}

LOCATIONS: dict[str, int] = {"New York": 30, "Boston": 20, "Austin": 15, "London": 15, "Remote": 15, "Toronto": 5}
LOCATION_SITE: dict[str, str] = {
    "New York": "New York HQ", "Boston": "Boston office", "Austin": "Austin office", "London": "London office",
    "Remote": "Remote", "Toronto": "Toronto office",
}
LOCATION_NET: dict[str, str] = {
    "New York": "10.41.0.0/16", "Boston": "10.40.0.0/16", "Austin": "10.43.0.0/16", "London": "10.42.0.0/16",
    "Remote": "10.99.0.0/16", "Toronto": "10.44.0.0/16",
}
LOCATION_EGRESS: dict[str, str] = {
    "New York": "198.51.100.201", "Boston": "198.51.100.202", "Austin": "198.51.100.204", "London": "198.51.100.203",
    "Remote": "198.51.100.200", "Toronto": "198.51.100.205",
}
LOCATION_OU: dict[str, str] = {
    "New York": "NYC", "Boston": "BOS", "Austin": "AUS", "London": "LON", "Remote": "REMOTE", "Toronto": "YYZ",
}
