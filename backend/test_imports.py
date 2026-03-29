try:
    import flask
    print(f"Flask imported {flask.__version__}")

    import numpy
    print(f"NumPy imported {numpy.__version__}")

    import jwt
    print(f"PyJWT imported {jwt.__version__}")

    import mysql.connector
    print("mysql connector installed")

    import sklearn
    print(f"Scikit-learn: {sklearn.__version__}")

    print("\nAll dependencies installed successfully")

except ImportError as e:
    print(f"Error: {e}")