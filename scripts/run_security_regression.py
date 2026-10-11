"""Invoke bounded contributor security checks without loading application settings."""

try:
    from security_regression.runner import main
except ImportError:
    print('{"reason":"dependency_missing"}')
    raise SystemExit(2) from None

if __name__ == "__main__":
    raise SystemExit(main())
