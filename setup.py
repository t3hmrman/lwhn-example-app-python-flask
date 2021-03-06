from setuptools import setup, find_packages

setup(
    name="lwhn_example_app_python_flask",
    version="1.0.0",
    packages=find_packages(where="."),
    package_dir={"": "."},
    install_requires=[
        "Flask-Session>=0.3.1",
        "attrs>=18.1.0",
        "flask-login>=0.4.1",
        "flask>=1.0",
        "gunicorn>=19.8.1",
        "requests>=2.19.1",
    ],
    entry_points={
        "console_scripts": [
            "app = lwhn_example_app_python_flask.app:app.run",
        ],
    },
)
