#!/usr/bin/env sh
# Build and run StegoShield using only a plain JDK 17 installation.
set -eu

MODE=${1:-build}

mkdir -p out
javac -Xlint:all -d out $(find src -name "*.java" -print)

case "$MODE" in
    build)
        printf '%s\n' "Build completed: out"
        ;;
    run)
        exec java -cp out ui.MainFrame
        ;;
    test)
        exec java -cp out test.StegoShieldSelfTest
        ;;
    eval)
        shift
        exec java -cp out eval.EvaluationRunner "$@"
        ;;
    verify-features)
        shift
        exec java -cp out demo.FeatureVerification "$@"
        ;;
    *)
        printf '%s\n' "Usage: ./build.sh [build|run|test|verify-features [samples-folder]|eval <clean-image-folder> [output-root]]" >&2
        exit 2
        ;;
esac
