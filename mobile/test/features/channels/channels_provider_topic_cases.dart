part of 'channels_provider_test.dart';

void _topicRefreshTests() {
  _canonicalTopicRefreshTests();
  for (final channelType in ['stream', 'forum']) {
    test(
      'live topic notices refresh the merged $channelType channel and independent caches',
      () async {
        final session = _FakeRelaySession(
          memberships: [
            _membership(_channelA, 'me'),
            _membership(_channelB, 'me'),
          ],
          metadata: [
            _meta(
              id: _channelA,
              name: 'general',
              channelType: channelType,
              topic: 'old topic',
            ),
            _meta(id: _channelB, name: 'other', topic: 'unrelated topic'),
          ],
        );
        final container = _buildContainer(session: session);
        addTearDown(container.dispose);
        final initial = await container.read(channelsProvider.future);
        final oldDetails = await container.read(
          channelDetailsProvider(_channelA).future,
        );
        final unrelated = await container.read(
          channelDetailsProvider(_channelB).future,
        );
        await _waitUntil(() => session.activeSubscriptionCount == 2);
        expect(
          initial
              .firstWhere((channel) => channel.id == _channelA)
              .mergeDetails(oldDetails)
              .topic,
          'old topic',
        );

        var index = 0;
        for (final topic in ['  "launch 🐝"  ', ' \t ', '']) {
          session.metadata = [
            _meta(
              id: _channelA,
              name: 'general',
              channelType: channelType,
              topic: topic,
              createdAt: 2 + index,
            ),
            session.metadata[1],
          ];
          session.emit(
            NostrEvent(
              id: 'topic-notice-${index++}',
              pubkey: 'f' * 64,
              createdAt: 10 + index,
              kind: EventKind.systemMessage,
              tags: [
                ['h', _channelA],
                ['buzz:workflow', 'true'],
                ['buzz:workflow-owner', 'a' * 64],
              ],
              content: jsonEncode({
                'type': 'topic_changed',
                'actor': 'a' * 64,
                'topic': topic,
              }),
              sig: 'sig',
            ),
          );
          await _settle();
          final expected = topic.isEmpty ? null : topic;
          final details = await container.read(
            channelDetailsProvider(_channelA).future,
          );
          final base = container
              .read(channelsProvider)
              .requireValue
              .firstWhere((channel) => channel.id == _channelA);
          expect(base.topic, expected);
          expect(details.topic, expected);
          expect(base.mergeDetails(details).topic, expected);
          expect(
            await container.read(channelDetailsProvider(_channelB).future),
            same(unrelated),
          );
        }
        // A metadata change must not churn the existing channel subscription.
        expect(session.totalSubscribeCount, 2);
      },
    );
  }

  test(
    'refresh invalidates old topic details after a missed live notice',
    () async {
      final session = _FakeRelaySession(
        memberships: [_membership(_channelA, 'me')],
        metadata: [_meta(id: _channelA, name: 'general', topic: 'old topic')],
      );
      final container = _buildContainer(session: session);
      addTearDown(container.dispose);
      await container.read(channelsProvider.future);
      await container.read(channelDetailsProvider(_channelA).future);
      session.metadata = [_meta(id: _channelA, name: 'general')];

      await container.read(channelsProvider.notifier).refresh();
      final refreshed = container.read(channelsProvider).requireValue.single;
      final details = await container.read(
        channelDetailsProvider(_channelA).future,
      );
      expect(refreshed.topic, isNull);
      expect(refreshed.mergeDetails(details).topic, isNull);
    },
  );
}

NostrEvent _topicNotice(String topic) => NostrEvent(
  id: 'human-topic-notice',
  pubkey: 'f' * 64,
  createdAt: 20,
  kind: EventKind.systemMessage,
  tags: [
    ['h', _channelA],
  ],
  content: jsonEncode({
    'type': 'topic_changed',
    'actor': 'a' * 64,
    'topic': topic,
  }),
  sig: 'sig',
);

void _canonicalTopicRefreshTests() {
  for (final topic in ['new topic', '']) {
    test(
      'canonical topic metadata converges after notice-before-metadata: "$topic"',
      () async {
        final session = _FakeRelaySession(
          memberships: [
            _membership(_channelA, 'me'),
            _membership(_channelB, 'me'),
          ],
          metadata: [
            _meta(id: _channelA, name: 'a', topic: 'old topic'),
            _meta(id: _channelB, name: 'b', topic: 'unrelated'),
          ],
        );
        final container = _buildContainer(session: session);
        addTearDown(container.dispose);
        await container.read(channelsProvider.future);
        await container.read(channelDetailsProvider(_channelA).future);
        final unrelated = await container.read(
          channelDetailsProvider(_channelB).future,
        );
        await _waitUntil(() => session.activeSubscriptionCount == 2);
        session.emit(_topicNotice(topic));
        await _settle();
        expect(
          (await container.read(
            channelDetailsProvider(_channelA).future,
          )).topic,
          'old topic',
        );
        session.metadata[0] = _meta(
          id: _channelA,
          name: 'a',
          topic: topic,
          createdAt: 30,
        );
        // Canonical events have d tags, and no h tag or workflow marker.
        session.emit(session.metadata[0]);
        await _settle();
        final details = await container.read(
          channelDetailsProvider(_channelA).future,
        );
        final base = container
            .read(channelsProvider)
            .requireValue
            .firstWhere((channel) => channel.id == _channelA);
        final expected = topic.isEmpty ? null : topic;
        expect(base.topic, expected);
        expect(base.mergeDetails(details).topic, expected);
        expect(
          await container.read(channelDetailsProvider(_channelB).future),
          same(unrelated),
        );
        expect(session.totalSubscribeCount, 2);
      },
    );

    test(
      'canonical topic invalidation retires an uncached initial detail response: "$topic"',
      () async {
        final old = _meta(id: _channelA, name: 'a', topic: 'old topic');
        final gate = Completer<List<NostrEvent>>();
        var detailCalls = 0;
        final session = _FakeRelaySession(
          memberships: [_membership(_channelA, 'me')],
          metadata: [old],
        );
        final container = _buildContainer(session: session);
        addTearDown(container.dispose);
        await container.read(channelsProvider.future);
        await _waitUntil(() => session.activeSubscriptionCount == 2);
        session.detailHistoryOverride = (_) {
          detailCalls++;
          return detailCalls == 1
              ? gate.future
              : Future.value(List.of(session.metadata));
        };
        addTearDown(() {
          if (!gate.isCompleted) gate.complete([old]);
        });
        container.listen(channelDetailsProvider(_channelA), (_, _) {});
        await _waitUntil(() => detailCalls == 1);
        session.metadata = [
          _meta(id: _channelA, name: 'a', topic: topic, createdAt: 30),
        ];
        session.emit(session.metadata.single);
        await _waitUntil(() => detailCalls >= 2);
        final expected = topic.isEmpty ? null : topic;
        final replacement = await container.read(
          channelDetailsProvider(_channelA).future,
        );
        expect(detailCalls, greaterThanOrEqualTo(2));
        expect(replacement.topic, expected);
        gate.complete([old]);
        await _settle();
        final details = await container.read(
          channelDetailsProvider(_channelA).future,
        );
        expect(details.topic, expected);
        expect(
          container
              .read(channelsProvider)
              .requireValue
              .single
              .mergeDetails(details)
              .topic,
          expected,
        );
      },
    );
  }
}
