#!/bin/bash
cd web-projects/ioc-correlation-engine
uvicorn app.main:app --host 0.0.0.0 --port $PORT
