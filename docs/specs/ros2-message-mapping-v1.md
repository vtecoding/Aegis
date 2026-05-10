# ROS 2 Message Mapping v1

## Scope

ROS 2 Message Mapping v1 describes how an approved abstract Aegis command would map to ROS 2
concepts later. It is inert data only. It does not import ROS packages, create nodes, publish
topics, call services, start actions, run launch files, or consult middleware defaults.

## Runtime Target

`RuntimeTarget` contains:

- `runtime_kind`
- `runtime_id`
- `runtime_version`
- `deployment_domain`
- `target_namespace`
- `target_robot_id`
- `runtime_authority`
- `runtime_target_checksum`

Phase 3 Part 1 supports `RuntimeKind.ROS2` only. The target is identity evidence, not
permission.

## QoS Profile

`Ros2QoSProfileSpec` requires explicit values for reliability, durability, history, depth,
deadline, lifespan, liveliness, lease duration, and checksum. `KEEP_ALL` is rejected in Phase 3
Part 1 because it implies unbounded queue behavior. `KEEP_LAST` requires a positive bounded
depth. No middleware QoS default is inferred.

## Message Mapping

`Ros2MessageMapping` contains:

- mapping ID and version
- source command and source capability
- communication primitive: topic, service, or action
- package name and message type
- namespace-scoped topic/service/action name
- namespace and optional frame ID
- explicit QoS profile
- explicit source-to-target field map
- required source fields
- forbidden runtime override fields
- mapping authority
- mapping checksum

Topic/service/action names are namespace-scoped only; absolute names are rejected. Field maps
are explicit. No reflection, fuzzy matching, best-effort matching, or implicit defaults are
allowed.

The forbidden fields must include:

- `disable_safety`
- `bypass_policy`
- `force_execute`
- `ignore_collision`
- `unsafe_mode`
- `override_limits`
- `raw_command`

These fields are forbidden as adapter evidence. Their rejection does not claim collision safety,
actuator safety, or physical robot safety.
