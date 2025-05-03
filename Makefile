.PHONY: test lint coverage clean

test:
	python -m unittest discover -s byob/tests

lint:
	flake8 byob

coverage:
	python -m coverage run --source=byob -m unittest discover -s byob/tests
	python -m coverage report -m
	python -m coverage html

clean:
	rm -rf htmlcov
	rm -f .coverage
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete
