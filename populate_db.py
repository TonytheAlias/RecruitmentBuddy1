import sqlite3
from pathlib import Path

def init_db():
    """Initialize the database with schema"""
    conn = sqlite3.connect('recruitmentbuddy.db')
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.close()
    print("Database initialized with schema.")

def populate_majors():
    """Populate the majors table with sample data"""
    conn = sqlite3.connect('recruitmentbuddy.db')
    cursor = conn.cursor()
    
    # Major data - using correct column names from schema.sql
    majors = [
        (
            "Computer Science",
            "Study of computation, programming, and information systems",
            "Software Engineer,Data Scientist,Systems Analyst",
            "Programming,Problem-solving,Mathematical reasoning",
            0.9, 0.6, 0.4, 0.9
        ),
        (
            "Psychology",
            "Study of human behavior and mental processes",
            "Counselor,Research Psychologist,Human Resources",
            "Active listening,Research,Empathy,Analysis",
            0.7, 0.5, 0.9, 0.3
        ),
        (
            "Graphic Design",
            "Visual communication and digital art creation",
            "UI/UX Designer,Brand Designer,Art Director",
            "Visual design,Creativity,Software proficiency",
            0.4, 0.9, 0.6, 0.7
        ),
        (
            "Mechanical Engineering",
            "Design and manufacturing of mechanical systems",
            "Product Designer,Manufacturing Engineer,R&D Engineer",
            "Mathematics,CAD,Problem-solving",
            0.9, 0.7, 0.5, 0.9
        ),
        (
            "Business Administration",
            "Management of business operations and strategy",
            "Business Manager,Entrepreneur,Consultant",
            "Leadership,Financial analysis,Communication",
            0.7, 0.6, 0.8, 0.5
        )
    ]
    
    # Insert majors - using correct column names
    cursor.executemany("""
        INSERT INTO majors (
            name, description, careers, skills,
            analytical_weight, creative_weight, social_weight, technical_weight
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, majors)
    
    conn.commit()
    conn.close()
    print("Successfully populated majors table.")

if __name__ == '__main__':
    # Initialize database with schema
    init_db()
    # Populate with sample data
    populate_majors()