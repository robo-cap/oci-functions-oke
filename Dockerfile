FROM fnproject/python:3.8
WORKDIR /function
ADD requirements.txt .
RUN python3 -m pip install -r requirements.txt
COPY func.py /function/
ENV PYTHONPATH="$PYTHONPATH:/function"
ENTRYPOINT ["fdk", "/function/func.py", "handler"]
