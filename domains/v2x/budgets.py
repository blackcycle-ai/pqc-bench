"""V2X (IEEE 1609.2 / ETSI TS 103 097) budgets — placeholder for migration.

The GOOSE domain (../goose/budgets.py) is the worked template. The V2X budget layer
to port from pqc-v2x-bench:

  SIZE  : CAM/DENM single-PDU size targets and the secured-message overhead of
          TS 103 097 / IEEE 1609.2 certificate attachment.
  RATE  : CAM generation cadence (1-10 Hz adaptive) -> per-message signing budget.

TODO: port the concrete numbers + the secured-message accounting from the upstream
pqc-v2x-bench repo, then express verdicts the same way GOOSE does, measured through
the homogeneous core harness.
"""

# Placeholders — fill from TS 103 097 / IEEE 1609.2 during migration.
CAM_MAX_HZ = 10            # adaptive CAM generation upper rate
# SECURED_OVERHEAD_BYTES = ...  # cert + signature attachment per TS 103 097
