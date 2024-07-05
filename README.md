FastAPI Tutorial


Setup

    python -m venv venv
    .\env\Scripts\activate
    pip install -r requirements.txt


If you're running Linux or MacOS you'll instead run

    python -m venv venv
    source ./env/bin/activate
    pip install -r requirements.txt


Running the app

    uvicorn main:app --reload
