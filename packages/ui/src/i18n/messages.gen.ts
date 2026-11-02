/* 自動生成: npm run i18n -w @oz/ui (packages/ui/i18n/generate.ts)。直接書き換えない。元は packages/ui/locales/*.yaml */

export const LOCALES = ["ja", "en"] as const;
export type Locale = (typeof LOCALES)[number];
export const BASE_LOCALE: Locale = "ja";

/** 文 (複数形の表は 区分 → 文) */
export type Message = string | Readonly<Record<string, string>>;

export type MessageKey =
  | "about.ozzy.intro"
  | "about.ozzy.li1"
  | "about.ozzy.li2"
  | "about.ozzy.li3"
  | "about.ozzy.li4"
  | "about.ozzy.li5"
  | "about.ozzy.li6"
  | "about.ozzy.li7"
  | "about.ozzy.title"
  | "about.route.intro"
  | "about.route.li1"
  | "about.route.li2"
  | "about.route.li3"
  | "about.route.li4"
  | "about.route.li5"
  | "about.route.title"
  | "about.safetyTitle"
  | "about.title"
  | "about.worker.intro"
  | "about.worker.step1"
  | "about.worker.step2"
  | "about.worker.step3"
  | "about.worker.title"
  | "app.close"
  | "app.keyLinkDropped"
  | "attach.button"
  | "attach.buttonLabel"
  | "attach.cancel"
  | "attach.counts"
  | "attach.empty"
  | "attach.encrypting"
  | "attach.failed"
  | "attach.inputLabel"
  | "attach.insufficientReplicas"
  | "attach.limitNote"
  | "attach.noFirstHop"
  | "attach.noHolders"
  | "attach.notReady"
  | "attach.pause"
  | "attach.paused"
  | "attach.progressLabel"
  | "attach.resume"
  | "attach.sending"
  | "attach.startFailed"
  | "attach.timingNote"
  | "attach.tooBig"
  | "board.cancel"
  | "board.colHeat"
  | "board.colThread"
  | "board.colUpdated"
  | "board.composeHint"
  | "board.copied"
  | "board.copyShare"
  | "board.create"
  | "board.empty"
  | "board.heading"
  | "board.idLabel"
  | "board.newThread"
  | "board.powRunning"
  | "board.public.dev"
  | "board.public.files"
  | "board.public.zatsudan"
  | "board.scoreTitle"
  | "board.shareTitle"
  | "board.sortHeat"
  | "board.sortLabel"
  | "board.sortNew"
  | "board.subject"
  | "board.titlePlaceholder"
  | "core.board.buildingThread"
  | "core.board.connectingNeighbors"
  | "core.board.createFailed"
  | "core.board.empty"
  | "core.board.latestFailed"
  | "core.board.spreading"
  | "core.board.syncingNeighbors"
  | "core.common.congestion"
  | "core.common.historyCount"
  | "core.common.historyFetching"
  | "core.common.historyStep"
  | "core.common.historyStepCount"
  | "core.common.initializing"
  | "core.common.noAnonymousRoute"
  | "core.thread.computedSending"
  | "core.thread.empty"
  | "core.thread.findingNeighbors"
  | "core.thread.historyLoading"
  | "core.thread.powRunning"
  | "core.thread.sendFailed"
  | "core.thread.sentWaiting"
  | "core.thread.syncError"
  | "core.thread.syncingPeers"
  | "core.thread.waitingNetwork"
  | "file.tokenLabel"
  | "fileCard.badLink"
  | "fileCard.cancel"
  | "fileCard.failed"
  | "fileCard.fetching"
  | "fileCard.fetchingInfo"
  | "fileCard.get"
  | "fileCard.getLabel"
  | "fileCard.noFirstHop"
  | "fileCard.notReady"
  | "fileCard.progressLabel"
  | "fileCard.save"
  | "fileCard.saveLabel"
  | "fileCard.sizeNote"
  | "fileCard.startFailed"
  | "fileCard.title"
  | "fileCard.tooBig"
  | "fileCard.unavailable"
  | "fileCard.visibleNote"
  | "guard.expired.detail2"
  | "guard.expired.headline"
  | "guard.expired.label"
  | "guard.fallback.detail1"
  | "guard.fallback.detail2"
  | "guard.fallback.headline"
  | "guard.fallback.label"
  | "guard.import.badGuard"
  | "guard.import.default"
  | "guard.import.expired"
  | "guard.import.insufficientSignatures"
  | "guard.import.malformed"
  | "guard.import.noKeyset"
  | "guard.import.notYetValid"
  | "guard.import.rollback"
  | "guard.import.tooLarge"
  | "guard.import.tooManyGuards"
  | "guard.import.validityTooLong"
  | "guard.noRoute.detail1"
  | "guard.noRoute.headline"
  | "guard.noRoute.label"
  | "guard.open.detail1"
  | "guard.open.detail2"
  | "guard.open.headline"
  | "guard.open.label"
  | "guard.pending.detail1"
  | "guard.pending.detail2"
  | "guard.pending.headline"
  | "guard.pending.label"
  | "guard.reason.listExpired"
  | "guard.reason.noList"
  | "guard.reason.noTrustedConnected"
  | "guard.reason.waitingCandidates"
  | "guard.reason.waitingTrusted"
  | "guard.trusted.detail1"
  | "guard.trusted.headline"
  | "guard.trusted.label"
  | "guard.weakConfirm.body1"
  | "guard.weakConfirm.body2"
  | "guard.weakConfirm.body3"
  | "guard.weakConfirm.cancel"
  | "guard.weakConfirm.proceed"
  | "guard.weakConfirm.title"
  | "guardPanel.close"
  | "guardPanel.import"
  | "guardPanel.importDesc"
  | "guardPanel.importTitle"
  | "guardPanel.imported"
  | "guardPanel.listExpires"
  | "guardPanel.listVersion"
  | "guardPanel.noKey"
  | "guardPanel.stopped"
  | "guardPanel.textLabel"
  | "guardPanel.title"
  | "hostGuard.copied"
  | "hostGuard.copy"
  | "hostGuard.counts"
  | "hostGuard.disable"
  | "hostGuard.enable"
  | "hostGuard.guardString"
  | "hostGuard.intro"
  | "hostGuard.listTitle"
  | "hostGuard.listed"
  | "hostGuard.loading"
  | "hostGuard.noList"
  | "hostGuard.notListed"
  | "hostGuard.openAtLogin"
  | "hostGuard.openAtLoginNote"
  | "hostGuard.slotOption"
  | "hostGuard.slots"
  | "hostGuard.stateOff"
  | "hostGuard.stateRunning"
  | "hostGuard.stateStarting"
  | "hostGuard.stateStopped"
  | "hostGuard.trackerDesc"
  | "hostGuard.trackerPortLabel"
  | "hostGuard.trackerPortPlaceholder"
  | "hostGuard.trackerString"
  | "hostGuard.trackerTitle"
  | "legal.a1.heading"
  | "legal.a1.p1"
  | "legal.a1.p2"
  | "legal.a1.p3"
  | "legal.a1.p4"
  | "legal.a10.heading"
  | "legal.a10.p1"
  | "legal.a10.p2"
  | "legal.a11.heading"
  | "legal.a11.p1"
  | "legal.a11.p2"
  | "legal.a2.heading"
  | "legal.a2.p1"
  | "legal.a2.p2"
  | "legal.a2.p3"
  | "legal.a2.p4"
  | "legal.a3.heading"
  | "legal.a3.item1"
  | "legal.a3.item2"
  | "legal.a3.item3"
  | "legal.a3.item4"
  | "legal.a3.item5"
  | "legal.a3.item6"
  | "legal.a3.item7"
  | "legal.a3.item8"
  | "legal.a3.p1"
  | "legal.a4.heading"
  | "legal.a4.p1"
  | "legal.a4.p2"
  | "legal.a5.heading"
  | "legal.a5.p1"
  | "legal.a5.p2"
  | "legal.a5.p3"
  | "legal.a6.heading"
  | "legal.a6.p1"
  | "legal.a7.heading"
  | "legal.a7.p1"
  | "legal.a8.heading"
  | "legal.a8.p1"
  | "legal.a8.p2"
  | "legal.a8.p3"
  | "legal.a9.heading"
  | "legal.a9.p1"
  | "legal.dateLabel"
  | "legal.preamble"
  | "legal.title"
  | "ozzyWorker.checking"
  | "ozzyWorker.done"
  | "ozzyWorker.locked"
  | "ozzyWorker.reason.badUrl"
  | "ozzyWorker.reason.direct"
  | "ozzyWorker.reason.notOzzy"
  | "ozzyWorker.reason.outdated"
  | "ozzyWorker.reason.unreachable"
  | "ozzyWorker.save"
  | "ozzyWorker.urlLabel"
  | "p2p.startFailed"
  | "p2p.stunFormat"
  | "p2p.stunMax"
  | "p2p.stunSaved"
  | "p2p.stunTurn"
  | "p2p.trackerSavedOffline"
  | "p2p.unlockFirst"
  | "p2p.wrongPassphrase"
  | "passphrase.fair"
  | "passphrase.short"
  | "passphrase.strong"
  | "passphrase.weak"
  | "postLimit.closed"
  | "postLimit.expired"
  | "postLimit.failed"
  | "postLimit.fullBytes"
  | "postLimit.note"
  | "postLimit.over"
  | "postLimit.remaining"
  | "postLimit.tooLong"
  | "security.can1"
  | "security.can2"
  | "security.can3"
  | "security.canTitle"
  | "security.cannot1"
  | "security.cannot2"
  | "security.cannot3"
  | "security.cannot4"
  | "security.cannot5"
  | "security.cannot6"
  | "security.cannotTitle"
  | "settings.navLabel"
  | "settings.ozzy.backendLabel"
  | "settings.ozzy.badUrl"
  | "settings.ozzy.batchLabel"
  | "settings.ozzy.change"
  | "settings.ozzy.checking"
  | "settings.ozzy.directNote"
  | "settings.ozzy.engineGatekeeper"
  | "settings.ozzy.engineLabel"
  | "settings.ozzy.engineOverseas"
  | "settings.ozzy.fastChunk"
  | "settings.ozzy.fastChunkNote"
  | "settings.ozzy.fetcher"
  | "settings.ozzy.fetcherNote"
  | "settings.ozzy.gkOnly"
  | "settings.ozzy.gkTitle"
  | "settings.ozzy.gkUrlLabel"
  | "settings.ozzy.idleLabel"
  | "settings.ozzy.knownWorkers"
  | "settings.ozzy.liveLockers"
  | "settings.ozzy.liveLockersNote"
  | "settings.ozzy.lockersTitle"
  | "settings.ozzy.maxWaitLabel"
  | "settings.ozzy.noResponse"
  | "settings.ozzy.ownWorker"
  | "settings.ozzy.register"
  | "settings.ozzy.registerFailed"
  | "settings.ozzy.registered"
  | "settings.ozzy.responded"
  | "settings.ozzy.slabTitle"
  | "settings.ozzy.storageTitle"
  | "settings.ozzy.switchFailed"
  | "settings.ozzy.workerTitle"
  | "settings.section.connection"
  | "settings.section.guard"
  | "settings.section.hostGuard"
  | "settings.section.ozzy"
  | "settings.section.storage"
  | "settings.title"
  | "settings.tracker.clear"
  | "settings.tracker.close"
  | "settings.tracker.cloudflare"
  | "settings.tracker.current"
  | "settings.tracker.deno"
  | "settings.tracker.desc"
  | "settings.tracker.placeholder"
  | "settings.tracker.reset"
  | "settings.tracker.save"
  | "settings.tracker.saved"
  | "settings.tracker.title"
  | "settings.tracker.unset"
  | "settings.tracker.urlLabel"
  | "sidebar.add"
  | "sidebar.anonymous"
  | "sidebar.badShare"
  | "sidebar.boards"
  | "sidebar.cancel"
  | "sidebar.createPrivate"
  | "sidebar.guardLabel"
  | "sidebar.guardTitle"
  | "sidebar.importHint"
  | "sidebar.importLabel"
  | "sidebar.join"
  | "sidebar.label"
  | "sidebar.lock"
  | "sidebar.lockTitle"
  | "sidebar.nav.about"
  | "sidebar.nav.board"
  | "sidebar.nav.settings"
  | "sidebar.nav.status"
  | "sidebar.nav.vault"
  | "sidebar.navLabel"
  | "sidebar.peersTitle"
  | "sidebar.publicShare"
  | "sidebar.status"
  | "sidebar.tracker"
  | "sidebar.trackerMissing"
  | "sidebar.trackerSettings"
  | "sidebar.trackerUnset"
  | "sidebar.tripLinked"
  | "sidebar.tripNote"
  | "sidebar.wipe"
  | "sidebar.wipeAgain"
  | "sidebar.wipeTitle"
  | "status.cell.dropped"
  | "status.cell.history"
  | "status.cell.leaseSets"
  | "status.cell.peers"
  | "status.cell.recent"
  | "status.cell.relayed"
  | "status.cell.route"
  | "status.cell.service"
  | "status.cell.slots"
  | "status.cell.tracker"
  | "status.eyebrow"
  | "status.gridLabel"
  | "status.log.clear"
  | "status.log.copied"
  | "status.log.copy"
  | "status.log.copyNote"
  | "status.log.empty"
  | "status.log.heavyNote"
  | "status.log.level.debug"
  | "status.log.level.info"
  | "status.log.level.trace"
  | "status.log.level.warn"
  | "status.log.newRows"
  | "status.log.pause"
  | "status.log.record"
  | "status.log.recordLabel"
  | "status.log.resume"
  | "status.log.rows"
  | "status.log.scope"
  | "status.log.scopeAll"
  | "status.log.search"
  | "status.log.searchLabel"
  | "status.log.selectedLabel"
  | "status.log.warnOnly"
  | "status.title"
  | "status.value.dropped"
  | "status.value.history"
  | "status.value.peers"
  | "status.value.recent"
  | "status.value.relayed"
  | "status.value.route"
  | "status.value.serviceGuard"
  | "status.value.serviceNormal"
  | "status.value.trackerConnected"
  | "status.value.trackerIdle"
  | "storage.close"
  | "storage.desc"
  | "storage.failed"
  | "storage.option"
  | "storage.saved"
  | "storage.slotsAria"
  | "storage.slotsLabel"
  | "storage.title"
  | "stun.default"
  | "stun.desc"
  | "stun.format"
  | "stun.inUse"
  | "stun.none"
  | "stun.placeholder"
  | "stun.reset"
  | "stun.resetButton"
  | "stun.save"
  | "stun.saved"
  | "stun.title"
  | "terms.gate.agree"
  | "terms.gate.bodyLabel"
  | "terms.gate.check"
  | "terms.gate.decline"
  | "terms.gate.declined"
  | "terms.gate.first"
  | "terms.gate.updated"
  | "thread.anonymous"
  | "thread.back"
  | "thread.boardLabel"
  | "thread.bytesNotice"
  | "thread.expiredNotice"
  | "thread.heading"
  | "thread.hidden"
  | "thread.nearBytes"
  | "thread.nearPosts"
  | "thread.newPosts"
  | "thread.overThread"
  | "thread.placeholder"
  | "thread.postsNotice"
  | "thread.quoteTitle"
  | "thread.send"
  | "thread.subject"
  | "transfer.confirmLeave"
  | "unlock.badge"
  | "unlock.confirm"
  | "unlock.forgot"
  | "unlock.generate"
  | "unlock.generateHint"
  | "unlock.generatedLabel"
  | "unlock.mismatch"
  | "unlock.noteDown"
  | "unlock.password"
  | "unlock.resetAgain"
  | "unlock.securityTitle"
  | "unlock.setupLead"
  | "unlock.setupSubmit"
  | "unlock.setupTitle"
  | "unlock.starting"
  | "unlock.strength"
  | "unlock.submit"
  | "unlock.tooShort"
  | "unlock.unlockLead"
  | "unlock.unlockTitle"
  | "vault.badLink"
  | "vault.badRingKey"
  | "vault.badVoucher"
  | "vault.chooseDestination"
  | "vault.chunksFailed"
  | "vault.circuitBuilding"
  | "vault.circuitReady"
  | "vault.colFailed"
  | "vault.colLocker"
  | "vault.colPlaced"
  | "vault.copied"
  | "vault.copy"
  | "vault.deleteFailed"
  | "vault.deleteFromLockers"
  | "vault.deleted"
  | "vault.deletedDone"
  | "vault.demoNote"
  | "vault.downloadFailed"
  | "vault.dropSub"
  | "vault.dropTitle"
  | "vault.error"
  | "vault.failure.aborted"
  | "vault.failure.badManifest"
  | "vault.failure.hashMismatch"
  | "vault.failure.insufficientShares"
  | "vault.failure.noFetchers"
  | "vault.failure.noManifest"
  | "vault.fetch"
  | "vault.fetchingManifestGk"
  | "vault.fetchingManifestP2p"
  | "vault.firstDesc"
  | "vault.firstTitle"
  | "vault.issuedTitle"
  | "vault.itemSize"
  | "vault.linkLabel"
  | "vault.linkPlaceholder"
  | "vault.madeLinks"
  | "vault.makeMemberKey"
  | "vault.manifestFailed"
  | "vault.manifestGone"
  | "vault.maxGiB"
  | "vault.memberKey"
  | "vault.mint"
  | "vault.mintDesc"
  | "vault.mintFailed"
  | "vault.mintTitle"
  | "vault.noCircuit"
  | "vault.pickCancelled"
  | "vault.placingManifest"
  | "vault.proxyProgress"
  | "vault.reading"
  | "vault.receiveDesc"
  | "vault.receiveTitle"
  | "vault.restored"
  | "vault.restoredBadge"
  | "vault.ringLabel"
  | "vault.ringPlaceholder"
  | "vault.ringTooSmall"
  | "vault.saveAndFetch"
  | "vault.saveToDevice"
  | "vault.saved"
  | "vault.sendDescGatekeeper"
  | "vault.sendDescOverseas"
  | "vault.sendTitle"
  | "vault.slabs"
  | "vault.spreadingDemo"
  | "vault.spreadingLive"
  | "vault.stepDone"
  | "vault.stepLockers"
  | "vault.stepManifest"
  | "vault.stepRead"
  | "vault.stepsLabel"
  | "vault.storageSettings"
  | "vault.stripePlaced"
  | "vault.stripesWritten"
  | "vault.tabTransfer"
  | "vault.tabVoucher"
  | "vault.tabsLabel"
  | "vault.title"
  | "vault.uploadDone"
  | "vault.uploadDoneR2"
  | "vault.uploadFailed"
  | "vault.validDays"
  | "vault.voucherLabel"
;

/** 差し込み ({name}) のあるキー → 渡す値。複数形のキーは count が数 */
export interface MessageParams {
  "attach.buttonLabel": { limit: string | number };
  "attach.counts": { needed: string | number; placed: string | number };
  "attach.insufficientReplicas": { counts: string | number };
  "attach.limitNote": { limit: string | number };
  "attach.tooBig": { limit: string | number; size: string | number };
  "board.heading": { name: string | number };
  "board.powRunning": { percent: string | number };
  "core.board.syncingNeighbors": { degree: string | number };
  "core.common.historyCount": { count: string | number };
  "core.common.historyStep": { done: string | number; total: string | number };
  "core.common.historyStepCount": { count: string | number; done: string | number; total: string | number };
  "core.thread.sendFailed": { error: string | number };
  "fileCard.fetching": { percent: string | number };
  "fileCard.getLabel": { size: string | number };
  "fileCard.saveLabel": { name: string | number };
  "fileCard.sizeNote": { size: string | number };
  "fileCard.title": { size: string | number };
  "fileCard.tooBig": { limit: string | number };
  "guardPanel.imported": { time: string | number; version: string | number };
  "guardPanel.listExpires": { time: string | number };
  "guardPanel.listVersion": { version: string | number };
  "hostGuard.counts": { backbone: string | number; clients: string | number; degree: string | number; tunnels: string | number };
  "hostGuard.listed": { version: string | number };
  "hostGuard.notListed": { version: string | number };
  "hostGuard.slotOption": { n: string | number; size: string | number };
  "hostGuard.trackerTitle": { port: string | number };
  "legal.dateLabel": { day: string | number; month: string | number; year: string | number };
  "passphrase.short": { n: string | number };
  "postLimit.note": { max: string | number; subject: string | number };
  "postLimit.over": { n: string | number };
  "postLimit.remaining": { n: string | number };
  "postLimit.tooLong": { max: string | number; subject: string | number };
  "settings.ozzy.checking": { url: string | number };
  "settings.ozzy.knownWorkers": { count: string | number };
  "settings.ozzy.ownWorker": { url: string | number };
  "settings.ozzy.registerFailed": { reason: string | number };
  "settings.ozzy.registered": { url: string | number };
  "settings.ozzy.switchFailed": { reason: string | number };
  "sidebar.guardLabel": { label: string | number };
  "sidebar.guardTitle": { headline: string | number };
  "status.log.newRows": { count: string | number };
  "status.log.rows": { shown: string | number; total: string | number };
  "status.value.dropped": { preVerify: string | number; rate: string | number; relay: string | number };
  "status.value.history": { attempts: string | number; fetches: string | number };
  "status.value.peers": { connected: string | number; max: string | number; verified: string | number };
  "status.value.recent": { posts: string | number; size: string | number };
  "status.value.relayed": { requests: string | number; size: string | number };
  "status.value.route": { label: string | number; middles: string | number };
  "storage.option": { n: string | number; size: string | number };
  "storage.slotsLabel": { size: string | number };
  "thread.anonymous": { trip: string | number };
  "thread.boardLabel": { name: string | number };
  "thread.heading": { id: string | number };
  "thread.hidden": { count: string | number };
  "thread.nearBytes": { kb: string | number };
  "thread.nearPosts": { count: string | number };
  "thread.newPosts": { count: string | number };
  "unlock.strength": { label: string | number };
  "unlock.tooShort": { min: string | number };
  "vault.badRingKey": { key: string | number };
  "vault.chooseDestination": { bytes: string | number; name: string | number };
  "vault.circuitReady": { count: string | number };
  "vault.deleteFailed": { reason: string | number };
  "vault.deleted": { ok: string | number; total: string | number };
  "vault.downloadFailed": { reason: string | number };
  "vault.error": { reason: string | number };
  "vault.itemSize": { bytes: string | number; count: string | number };
  "vault.mintFailed": { reason: string | number };
  "vault.proxyProgress": { done: string | number; k: string | number; n: string | number; total: string | number };
  "vault.restored": { name: string | number };
  "vault.saved": { bytes: string | number; name: string | number };
  "vault.slabs": { count: string | number; lockers: string | number };
  "vault.spreadingLive": { lockers: string | number };
  "vault.stepLockers": { count: string | number };
  "vault.stripePlaced": { done: string | number; total: string | number };
  "vault.stripesWritten": { done: string | number; total: string | number };
  "vault.uploadDone": { lockers: string | number; names: string | number; slabs: string | number };
  "vault.uploadFailed": { reason: string | number };
}

/** 部品の印 (<link>…</link>・<br/>) のあるキー → 印の名前 */
export interface MessageTags {
  "about.ozzy.li3": "code";
  "about.worker.step2": "code";
  "about.worker.step3": "code";
  "hostGuard.intro": "strong";
  "settings.ozzy.ownWorker": "code";
  "vault.firstDesc": "link";
  "vault.slabs": "strong";
}

export const MESSAGES: Readonly<Record<Locale, Readonly<Partial<Record<MessageKey, Message>>>>> = {
  "ja": {
    "about.ozzy.intro": "共有ファイルは端末内で暗号化して 64 MiB ごとのストライプに分割され、Reed-Solomon 符号により 32 個のシェア (任意の 16 個から元通り復元可能) に冗長化して複数の公開ファイルロッカーへ分散配置されます。一部のロッカーが削除・停止しても安全に取り出せます。",
    "about.ozzy.li1": "ロッカーへのアップロードおよびダウンロードは、本端末ではなくオニオン回路先の M1 中継ノードが代理実行します。M1 は他の参加者が提供する中継 Worker を通してロッカーへアクセスするため、ロッカーにも Worker にもあなたの IP アドレスは届きません。回路が確立できないときは処理を中断し、直接通信することはありません。",
    "about.ozzy.li2": "アップロード直後に別経路からダウンロードを試行し、正常に配置されたかを即座に検証します。取得したシェアはハッシュ値で検証され、不正なデータを返したノードは自動的に排除されます。",
    "about.ozzy.li3": "配置情報（Manifest）は暗号化されて P2P ストレージに分散保持され、共有リンク <code>[[ozzy:v3:…]]</code> 自体がその復号鍵となります。中央サーバーや公開ディレクトリは使用しません。",
    "about.ozzy.li4": "Guard ノードには、アップロードされた総通信量が観測されます (誤り訂正パリティを含むため、ファイル実サイズの約 2 倍となります)。",
    "about.ozzy.li5": "公開ロッカーはファイルの自主削除や保存期限切れが発生する場合がありますが、全体の半分（最大 16/32 シェア）が消失しても元のファイルを完全に復元できます。",
    "about.ozzy.li6": "Internet Archive は使用しません。個人アカウントでのアップロードが必要となり、アカウント情報から身元が特定されるリスクがあるためです。",
    "about.ozzy.li7": "保存先を Gatekeeper Worker に指定した場合、Gatekeeper と直接通信するため、Worker 側のアクセスログにあなたの IP アドレスが記録されます。",
    "about.ozzy.title": "ファイル共有 (Ozzy)",
    "about.route.intro": "送信データは、あなた → Guard (直接接続する第 1 ホップ) → M1 (Guard 先の中継ピア) による 2 段の暗号経路を経由します。データは 1,200 バイト固定長のセルに分割され、全ノードが常時送出しているダミーセルに混入させて送信されます。",
    "about.route.li1": "Guard に見えるのは、あなたの IP アドレス、セルを通信している事実、およびその通信量のみです。ダミーセルが混ざるため、実際のデータ送信タイミングは特定されません。",
    "about.route.li2": "M1 に見えるのは通信の宛先 (取得先 URL 等) と手前の Guard だけであり、あなたの IP アドレスは伝達されません。",
    "about.route.li3": "Guard と M1 の双方が同一の攻撃者に掌握されている場合、あなたと送信先が結び付きます (Tor と同様の構造的限界)。信頼 Guard を設定することで、この結託リスクを低減できます。",
    "about.route.li4": "掲示板の投稿は M1 の先でさらに複数のピアを経由して P2P ネットワーク全体へ拡散されるため、最初にネットワークへ流出させたノードとしてあなたや Guard が特定されることはありません。",
    "about.route.li5": "Guard と M1 には、あなたと同じネットワーク (同一 LAN・同一パブリック IP) のノードは選定されません。1 台の端末で複数のノードを起動しても自身のノードのみで経路が構成されることはなく、外部ピアが発見されるまで「匿名経路を準備中」の待機状態となります。",
    "about.route.title": "匿名経路",
    "about.safetyTitle": "守れること・守れないこと",
    "about.title": "仕組みと安全性",
    "about.worker.intro": "ファイル共有を利用する場合、Cloudflare Workers 上に中継用 Worker を各自 1 つデプロイします。デプロイした Worker は、他の参加者の中継ノード (M1) がロッカーへアクセスする際のプロキシとして相互利用されます。Worker の URL は P2P ネットワーク経由で他の参加者に共有されます。",
    "about.worker.step1": "Cloudflare アカウントを作成します。本名や普段利用しているメールアドレスと結び付かないアカウントとし、workers.dev のサブドメインにも身元が推測されない名前を設定してください。",
    "about.worker.step2": "配布ページ (<code>https://github.com/jkfujinami/Oz/releases/latest</code>) から <code>OZ-worker-<版>.zip</code> をダウンロードし、同梱の README.txt の手順で Worker をデプロイします。Cloudflare の管理画面にコードを貼り付ける方法であれば、追加ツールのインストールやクレジットカードの登録は不要です。",
    "about.worker.step3": "発行された <code>https://….workers.dev</code> の URL を、「設定」→「ファイル共有」に登録します。",
    "about.worker.title": "中継 Worker",
    "app.close": "閉じる",
    "app.keyLinkDropped": "リンクに含まれていた板の鍵は受け付けていません (閲覧履歴に残るため)。 共有コードを受け取っている場合は、サイドバーの「共有コードで参加」に貼り付けてください。",
    "attach.button": "添付",
    "attach.buttonLabel": "ファイルを添付 (1 つ、{limit} まで)",
    "attach.cancel": "中止",
    "attach.counts": "(保持ノード {needed} か所が必要で、配置完了は {placed} か所)",
    "attach.empty": "空のファイルは添付できません。",
    "attach.encrypting": "暗号化中",
    "attach.failed": "アップロードに失敗しました。もう一度お試しください。",
    "attach.inputLabel": "添付するファイル",
    "attach.insufficientReplicas": "保持ノードが不足しているため、完全に配置できませんでした (置ききれませんでした){counts}。ファイルサイズではなく、現在応答可能なノード数による制約です。しばらく待ってから再度お試しください。",
    "attach.limitNote": "1 つ・{limit} まで",
    "attach.noFirstHop": "ネットワークに接続されていません。接続が確立するまでお待ちください。",
    "attach.noHolders": "保存先の保持ノードが見つかりませんでした。しばらく待ってから再度お試しください。",
    "attach.notReady": "準備ができていません。",
    "attach.pause": "一時停止",
    "attach.paused": "一時停止中",
    "attach.progressLabel": "アップロードの進み具合",
    "attach.resume": "再開",
    "attach.sending": "保管先へ送信中",
    "attach.startFailed": "アップロードを始められませんでした。",
    "attach.timingNote": "アップロード時刻とファイルサイズは、最初の中継先とプロバイダから見えます。置き終えてから数分あけて書き込むと、投稿と結び付けられにくくなります。",
    "attach.tooBig": "大きすぎます ({size})。上限は {limit} です。",
    "board.cancel": "中止",
    "board.colHeat": "勢い",
    "board.colThread": "スレッド",
    "board.colUpdated": "最終更新",
    "board.composeHint": "スレッドの本文（1レス目）を入力してください。送信時に端末内で Proof-of-Work (計算証明) を行います。",
    "board.copied": "コピーしました",
    "board.copyShare": "共有コードをコピー",
    "board.create": "作成",
    "board.empty": "スレッドはまだありません。「新スレを立てる」から投稿してください。",
    "board.heading": "板: {name}",
    "board.idLabel": "ID: ",
    "board.newThread": "新スレを立てる",
    "board.powRunning": "PoW計算中... {percent}%",
    "board.public.dev": "開発",
    "board.public.files": "ファイル共有スレッド",
    "board.public.zatsudan": "雑談",
    "board.scoreTitle": "スコア (PoW 計算量と新着度)",
    "board.shareTitle": "この板の暗号鍵を含みます。信頼できる相手にのみ共有してください",
    "board.sortHeat": "勢い",
    "board.sortLabel": "並び順",
    "board.sortNew": "新着",
    "board.subject": "スレッドタイトル",
    "board.titlePlaceholder": "スレッドタイトル...",
    "core.board.buildingThread": "スレッドを構築中...",
    "core.board.connectingNeighbors": "ピアを探索中 (接続試行中)...",
    "core.board.createFailed": "スレッドの作成に失敗しました",
    "core.board.empty": "スレッドが見つかりませんでした。「新スレを立てる」から作成してください。",
    "core.board.latestFailed": "最新スレッドの取得に失敗しました",
    "core.board.spreading": "拡散中...",
    "core.board.syncingNeighbors": "{degree} 件のピアと同期中...",
    "core.common.congestion": "混雑しているため、送信の準備に少し時間がかかります",
    "core.common.historyCount": "過去ログを取得中... ({count}件)",
    "core.common.historyFetching": "過去ログを取得中...",
    "core.common.historyStep": "過去ログを取得中... ({done}/{total})",
    "core.common.historyStepCount": "過去ログを取得中... ({done}/{total}・{count}件)",
    "core.common.initializing": "初期化中...",
    "core.common.noAnonymousRoute": "匿名経路で送信できませんでした (平文での送信は行っていません)。接続ピアが増加してから再度お試しください。",
    "core.thread.computedSending": "PoW 計算完了、送信中...",
    "core.thread.empty": "投稿がありません。最初の投稿を書き込んでください。",
    "core.thread.findingNeighbors": "ピアを探索中...",
    "core.thread.historyLoading": "過去ログを読み込み中...",
    "core.thread.powRunning": "PoW 計算中...",
    "core.thread.sendFailed": "🔴 失敗: {error}",
    "core.thread.sentWaiting": "送信完了 (配信待機中...)",
    "core.thread.syncError": "同期中にエラーが発生しました",
    "core.thread.syncingPeers": "ピアと同期中...",
    "core.thread.waitingNetwork": "ネットワーク接続待機中... 他のピアから投稿を受信すると自動で反映されます。",
    "file.tokenLabel": "[添付ファイル]",
    "fileCard.badLink": "このリンクは読み取れませんでした。",
    "fileCard.cancel": "中止",
    "fileCard.failed": "取得に失敗しました。もう一度お試しください。",
    "fileCard.fetching": "取得中 ({percent}%)",
    "fileCard.fetchingInfo": "情報を取得中",
    "fileCard.get": "取得",
    "fileCard.getLabel": "添付ファイルを取得 ({size})",
    "fileCard.noFirstHop": "ネットワークに接続されていません。しばらく待ってから再度お試しください。",
    "fileCard.notReady": "準備ができていません。",
    "fileCard.progressLabel": "取得の進み具合",
    "fileCard.save": "保存",
    "fileCard.saveLabel": "{name} を保存",
    "fileCard.sizeNote": " ({size})",
    "fileCard.startFailed": "取得を始められませんでした。",
    "fileCard.title": "添付ファイル ({size})",
    "fileCard.tooBig": "大きすぎて、このブラウザでは取得できません (上限 {limit})。デスクトップ版をお使いください。",
    "fileCard.unavailable": "ファイルが見つかりませんでした。保持期間が経過したか、保存先ノードがオフラインの可能性があります。",
    "fileCard.visibleNote": "取得すると、最初の中継ノードにはファイルを取得している事実が観測されます。",
    "guard.expired.detail2": "準備が整うと投稿は送信されますが、送信元の匿名性が低下している状態です。",
    "guard.expired.headline": "信頼リストが期限切れのため、未検証のピアによる匿名経路を準備しています。",
    "guard.expired.label": "警告: 信頼リストが期限切れ",
    "guard.fallback.detail1": "最初の中継は審査されていない普通の隣人 (未検証ピア) です。送信元の匿名性が低下しています。",
    "guard.fallback.detail2": "信頼 Guard への接続が復旧次第、自動で切り替わります。",
    "guard.fallback.headline": "信頼 Guard に接続できていません。",
    "guard.fallback.label": "警告: 信頼 Guard に未接続",
    "guard.import.badGuard": "Guard の記述に問題があります (署名か形式を確認してください)",
    "guard.import.default": "リストをインポートできませんでした",
    "guard.import.expired": "期限切れのリストです",
    "guard.import.insufficientSignatures": "メンテナの署名が足りません",
    "guard.import.malformed": "リストの形式が正しくありません",
    "guard.import.noKeyset": "このバージョンのアプリにはメンテナの公開鍵が組み込まれていません",
    "guard.import.notYetValid": "まだ有効になっていないリストです (発行時刻が未来です)",
    "guard.import.rollback": "手元のリストより古い版です",
    "guard.import.tooLarge": "リストが大きすぎます",
    "guard.import.tooManyGuards": "Guard の数が上限を超えています",
    "guard.import.validityTooLong": "有効期間が長すぎるリストです",
    "guard.noRoute.detail1": "原因が解消されるまでお待ちください。",
    "guard.noRoute.headline": "匿名経路を確立できていないため、投稿は送信されません。",
    "guard.noRoute.label": "警告: 匿名経路を確立できません",
    "guard.open.detail1": "最初の中継は審査されていない普通の隣人 (未検証ピア) です。送信元の匿名性が低下しています。",
    "guard.open.detail2": "このバージョンのアプリにはメンテナの公開鍵が組み込まれていないか、信頼リストが登録されていません。",
    "guard.open.headline": "信頼 Guard のリストが設定されていません。",
    "guard.open.label": "警告: 信頼 Guard 未設定",
    "guard.pending.detail1": "起動直後は確立まで数十秒ほどかかることがあります。通常の処理であり、エラーではありません。",
    "guard.pending.detail2": "準備が整うまで、投稿は送信されずに待ちます。",
    "guard.pending.headline": "匿名経路を確立しています。",
    "guard.pending.label": "匿名経路を準備中…",
    "guard.reason.listExpired": "登録済みの信頼リストが期限切れです。最新のリストをインポートしてください。",
    "guard.reason.noList": "信頼リストが未設定です。",
    "guard.reason.noTrustedConnected": "信頼リストに登録された Guard に現在接続できていません。",
    "guard.reason.waitingCandidates": "中継候補ノードを探索しています。",
    "guard.reason.waitingTrusted": "信頼 Guard への接続を待機しています。",
    "guard.trusted.detail1": "最初のホップ（中継）は、メンテナが審査した信頼リストに掲載されている Guard です。",
    "guard.trusted.headline": "信頼 Guard 経由で接続しています。",
    "guard.trusted.label": "信頼 Guard 経由",
    "guard.weakConfirm.body1": "現在、最初の中継が審査されていない普通の相手 (未検証ピア) になっています (信頼できる Guard に接続できていません)。",
    "guard.weakConfirm.body2": "この状態で投稿すると、悪意のあるピアを経由した場合、発信元があなたであると特定されるリスクが高まります。",
    "guard.weakConfirm.body3": "信頼できる Guard への接続が完了するまで待機することで、より安全に投稿できます。",
    "guard.weakConfirm.cancel": "やめる",
    "guard.weakConfirm.proceed": "それでも投稿する",
    "guard.weakConfirm.title": "送信元が特定されやすい状態です",
    "guardPanel.close": "閉じる",
    "guardPanel.import": "取り込む",
    "guardPanel.importDesc": "メンテナが署名した Guard リストの文字列を入力してください。署名と有効期限を確認してから保存します。",
    "guardPanel.importTitle": "信頼リストの取り込み",
    "guardPanel.imported": "取り込みました (版 {version}・期限 {time})",
    "guardPanel.listExpires": "・期限 {time}",
    "guardPanel.listVersion": "信頼リスト: 版 {version}",
    "guardPanel.noKey": "このバージョンのアプリには信頼リストの公開鍵が組み込まれていないため、リストをインポートできません。",
    "guardPanel.stopped": "リストを取り込めませんでした (ノードが停止しています)",
    "guardPanel.textLabel": "信頼リストの文字列",
    "guardPanel.title": "匿名経路の状態",
    "hostGuard.copied": "コピーしました",
    "hostGuard.copy": "コピー",
    "hostGuard.counts": "接続 {degree} (利用者 {clients} / 他の Guard {backbone})・トンネル {tunnels} 本",
    "hostGuard.disable": "Guard を止める",
    "hostGuard.enable": "Guard として動かす",
    "hostGuard.guardString": "Guard 文字列",
    "hostGuard.intro": "この端末を、他の利用者の 1 ホップ目 (信頼 Guard) として動かします。画面のノードとは別の身元で、画面をロックしても動き続けます。<strong> Guard には利用者の IP が見え、この端末の IP は Guard として利用者に見えます。</strong>",
    "hostGuard.listTitle": "信頼リスト",
    "hostGuard.listed": "この Guard は信頼リスト (v{version}) に載っています。",
    "hostGuard.loading": "読み込んでいます...",
    "hostGuard.noList": "このアプリには信頼リストがありません。下の Guard 文字列をメンテナに渡してください。",
    "hostGuard.notListed": "信頼リスト (v{version}) にはまだ載っていません。下の Guard 文字列をメンテナに渡してください。",
    "hostGuard.openAtLogin": "ログイン時に起動する",
    "hostGuard.openAtLoginNote": " (画面は出さず、トレイと Guard だけで動きます)",
    "hostGuard.slotOption": "{n} 枠 ({size} MiB)",
    "hostGuard.slots": "預かる枠",
    "hostGuard.stateOff": "使っていません",
    "hostGuard.stateRunning": "動いています",
    "hostGuard.stateStarting": "起動しています...",
    "hostGuard.stateStopped": "止まっています",
    "hostGuard.trackerDesc": "この文字列をトラッカー設定に入力すると、IP アドレスやポート番号を公開せずにこの端末のトラッカーへ接続できます。",
    "hostGuard.trackerPortLabel": "トラッカー開放ポート (任意)",
    "hostGuard.trackerPortPlaceholder": "例: 8787",
    "hostGuard.trackerString": "トラッカー文字列",
    "hostGuard.trackerTitle": "ポート開放トラッカー (ポート {port})",
    "legal.a1.heading": "第1条（本ソフトウェアの性質）",
    "legal.a1.p1": "本ソフトウェアは、利用者の端末どうしが直接通信する P2P（ピア・ツー・ピア）型のソフトウェアです。通信の秘匿性とプライバシーを守り、適法な情報のやり取りを支援することを目的として開発しています。",
    "legal.a1.p2": "本ソフトウェアの開発者（以下「開発者」といいます）は、本ソフトウェアによって形成されるネットワークを運営・管理していません。利用者が送受信、投稿または共有する情報（以下「コンテンツ」といいます）を閲覧、監視、管理または削除する立場になく、そのための技術的な手段も持っていません。",
    "legal.a1.p3": "開発者は、著作権侵害その他の違法な目的で本ソフトウェアを利用することを推奨せず、認めません。",
    "legal.a1.p4": "本ソフトウェアは開発段階の試験的なソフトウェアであり、第三者による安全性の監査を受けていません。",
    "legal.a10.heading": "第10条（本規約の変更）",
    "legal.a10.p1": "開発者は、必要に応じて本規約を変更することがあります。変更後の本規約は、本ソフトウェアまたは配布ページに掲載した時点から効力を生じます。",
    "legal.a10.p2": "本規約を変更した場合、本ソフトウェアは利用者に改めて同意を求めます。",
    "legal.a11.heading": "第11条（準拠法および管轄裁判所）",
    "legal.a11.p1": "本規約は日本法に準拠し、日本法に従って解釈されます。",
    "legal.a11.p2": "本規約または本ソフトウェアに関して紛争が生じた場合は、開発者の住所地を管轄する地方裁判所を第一審の専属的合意管轄裁判所とします。",
    "legal.a2.heading": "第2条（法令の遵守）",
    "legal.a2.p1": "利用者は、本ソフトウェアを利用する国または地域の法令（日本国内で利用する場合は日本の法令）を遵守しなければなりません。",
    "legal.a2.p2": "本ソフトウェアの利用が法令により禁止または制限されている国または地域では、本ソフトウェアを利用しないでください。",
    "legal.a2.p3": "未成年の方は、親権者などの法定代理人の同意を得たうえで本ソフトウェアを利用してください。",
    "legal.a2.p4": "利用者は、本ソフトウェアの利用およびコンテンツについて、自らの責任を負うものとします。",
    "legal.a3.heading": "第3条（禁止事項）",
    "legal.a3.item1": "著作権、著作隣接権、商標権その他の知的財産権を侵害する行為。権利者の許諾を得ずに、映画、音楽、アニメ、漫画、書籍、ゲーム、ソフトウェアその他の著作物をアップロード、共有または送信可能な状態にする行為、および違法にアップロードされたものと知りながらダウンロードする行為を含みます。",
    "legal.a3.item2": "児童ポルノ、わいせつな情報その他、法令により所持、頒布または公開が禁止されている情報を送信、共有または保存する行為",
    "legal.a3.item3": "他人の名誉または信用を傷つける行為、他人のプライバシーまたは肖像権を侵害する行為、および個人情報を本人の同意なく公開する行為",
    "legal.a3.item4": "脅迫、嫌がらせ、差別を助長する行為、犯罪の予告その他、他人に危害を加え、または加えるおそれのある行為",
    "legal.a3.item5": "詐欺、違法な薬物や武器の取引、マネー・ローンダリングその他の犯罪行為、およびこれらを助長し、または手助けする行為",
    "legal.a3.item6": "コンピュータウイルスなどの有害なプログラムを送信または共有する行為、不正アクセス行為、および他人の端末やネットワークの正常な動作を妨げる行為",
    "legal.a3.item7": "本ソフトウェア、他の利用者が運用する中継またはファイル置き場その他の外部サービスに過度の負荷をかける行為、およびそれらのサービスの利用規約に違反する行為",
    "legal.a3.item8": "その他、法令または公序良俗に違反する行為、またはそのおそれのある行為",
    "legal.a3.p1": "利用者は、本ソフトウェアの利用にあたり、次の行為をしてはなりません。",
    "legal.a4.heading": "第4条（外部サービスの利用）",
    "legal.a4.p1": "本ソフトウェアは、トラッカー、STUN サーバー、Cloudflare Workers、公開のファイル置き場など、第三者が提供するサービスを利用します。利用者は、これらのサービスの利用規約を自ら確認し、遵守するものとします。",
    "legal.a4.p2": "開発者は、これらのサービスの内容、可用性およびデータの取り扱いについて、責任を負いません。",
    "legal.a5.heading": "第5条（中継および Guard としての動作）",
    "legal.a5.p1": "本ソフトウェアは、その仕組み上、利用者の端末を通じて他の利用者の暗号化された通信を中継します。また、利用者が設定した場合には、他の利用者の最初の中継点（Guard）として動作します。",
    "legal.a5.p2": "中継される通信は暗号化されており、中継する利用者も開発者も、その内容を知ることはできません。利用者は、この仕組みを理解したうえで本ソフトウェアを利用するものとします。",
    "legal.a5.p3": "Guard として動作させる場合や中継用の Worker を運用する場合、利用者は自らの判断と責任において行うものとします。",
    "legal.a6.heading": "第6条（権利侵害の申告）",
    "legal.a6.p1": "開発者は、ネットワーク上のコンテンツを削除する手段を持っていません。権利を侵害するコンテンツを見つけた場合は、そのコンテンツを保存しているファイル置き場の運営者、または警察などの適切な窓口にご相談ください。",
    "legal.a7.heading": "第7条（無保証）",
    "legal.a7.p1": "本ソフトウェアは現状のまま提供されます。開発者は、本ソフトウェアに不具合や脆弱性がないこと、匿名性や秘匿性が確保されること、データが失われないこと、特定の目的に適合することなどについて、明示または黙示を問わず、いかなる保証もいたしません。",
    "legal.a8.heading": "第8条（免責）",
    "legal.a8.p1": "開発者は、本ソフトウェアを利用したこと、または利用できなかったことにより利用者または第三者に生じた損害（データの消失、身元の特定、法的な紛争などを含みます）について、責任を負いません。ただし、開発者の故意または重大な過失による場合は、この限りではありません。",
    "legal.a8.p2": "本ソフトウェアの利用またはコンテンツに関して、利用者と他の利用者または第三者との間で紛争が生じた場合、利用者は自らの責任と費用でこれを解決するものとし、開発者は関与しません。",
    "legal.a8.p3": "利用者が本規約に違反したことにより、または本ソフトウェアの利用に関して、開発者が第三者から請求を受け、または損害を被った場合、利用者はその損害（合理的な弁護士費用を含みます）を賠償するものとします。",
    "legal.a9.heading": "第9条（ソフトウェアのライセンス）",
    "legal.a9.p1": "本ソフトウェアの複製、改変および再頒布の条件は、本ソフトウェアに付属する MIT ライセンスに従います。",
    "legal.dateLabel": "{year}年{month}月{day}日 制定",
    "legal.preamble": "この利用規約（以下「本規約」といいます）は、OZ（Oz Protocol）のデスクトップ版、Web 版およびこれらに付随するプログラム（以下「本ソフトウェア」といいます）の利用条件を定めるものです。本ソフトウェアを利用する方（以下「利用者」といいます）は、本規約に同意したうえで本ソフトウェアを利用するものとします。本ソフトウェアを利用した時点で、利用者は本規約に同意したものとみなします。",
    "legal.title": "OZ 利用規約",
    "ozzyWorker.checking": "接続確認中...",
    "ozzyWorker.done": "設定完了",
    "ozzyWorker.locked": "ロックを解除してから設定してください",
    "ozzyWorker.reason.badUrl": "https://<名前>.<サブドメイン>.workers.dev の形式で入力してください (独自ドメインは利用できません)",
    "ozzyWorker.reason.direct": "デスクトップ版は中継 Worker を使用しません (ロッカーへ直接接続します)",
    "ozzyWorker.reason.notOzzy": "OZ の中継 Worker として認識できませんでした。配布ページの OZ-worker を設置してください",
    "ozzyWorker.reason.outdated": "Worker のバージョンが古いため利用できません。最新の OZ-worker を再デプロイしてください",
    "ozzyWorker.reason.unreachable": "Worker に接続できません。デプロイが完了しているか、URL が正しいか確認してください",
    "ozzyWorker.save": "検証して保存",
    "ozzyWorker.urlLabel": "中継 Worker の URL",
    "p2p.startFailed": "起動に失敗しました",
    "p2p.stunFormat": "stun:ホスト名:ポート の形で入力してください (複数ならカンマ区切り)",
    "p2p.stunMax": "STUN は 4 つまでです",
    "p2p.stunSaved": "保存しました。次回確立する接続から使います",
    "p2p.stunTurn": "TURN には対応していません (stun: で始まる URL だけ)",
    "p2p.trackerSavedOffline": "保存しました。現在はトラッカーに接続できませんでした (自動で再試行します)",
    "p2p.unlockFirst": "ロックを解除してください",
    "p2p.wrongPassphrase": "パスワードが違います",
    "passphrase.fair": "普通: もう少し長いとより安全です",
    "passphrase.short": "短すぎます (あと {n} 文字)",
    "passphrase.strong": "強い",
    "passphrase.weak": "弱い: 長さや文字の種類を増やしてください",
    "postLimit.closed": "このスレッドは投稿数上限に達したため、書き込めませんでした。入力内容は保持されています。新しいスレッドを立ててください。",
    "postLimit.expired": "このスレッドは期限切れ（過去ログ化）のため、書き込めませんでした。入力内容は保持されています。",
    "postLimit.failed": "送信に失敗しました。入力内容は保持されています。しばらく待ってから再度お試しください。",
    "postLimit.fullBytes": "この書き込みを追加するとスレッド容量上限を超過します。送信は行われていません。内容を短くするか、新しいスレッドに投稿してください。",
    "postLimit.note": "{subject}は {max} バイトまでです",
    "postLimit.over": "上限を {n} バイト超えています",
    "postLimit.remaining": "残り {n} バイト",
    "postLimit.tooLong": "{subject}は {max} バイトまでです。送信は行われていません。入力内容は保持されています。",
    "security.can1": "P2P ネットワーク上の観測者 (ピア・中継ノード・保管ノード) に対し、「どの投稿を誰が書いたか」を秘匿します。投稿はダミー通信に多重混入された暗号化経路経由で送信されます。",
    "security.can2": "本端末に保存されるデータ (投稿履歴・板の暗号鍵など) はパスワードで暗号化されます。推測されにくい十分な長さのパスワードであれば、ロック中や電源オフ時に押収されても読み取れません。",
    "security.can3": "板の鍵を持たない第三者には、投稿本文は読み取れません。",
    "security.canTitle": "守れること",
    "security.cannot1": "OZ を使っていること自体。あなたの IP アドレスは接続先の端末、トラッカーの運営者、通信事業者 (ISP)、STUN の運営者 (既定では Google と Cloudflare) から見えます。端末に OZ が入っていることも隠せません。",
    "security.cannot2": "国全体の通信を監視できる相手。そのような環境での告発には使わないでください。",
    "security.cannot3": "職場など所属組織のネットワークや端末からの利用。組織内の調査では、利用者であること自体から特定され得ます。",
    "security.cannot4": "ロックを解除した状態での端末の押収・物理アクセス。離席時は必ずロックしてください。",
    "security.cannot5": "トリップを使った投稿同士は、同じ人物のものとして紐付きます。",
    "security.cannot6": "投稿本文に含まれる情報 (関係者しか知り得ない事実、特有の文体など) からの特定。",
    "security.cannotTitle": "守れないこと",
    "settings.navLabel": "設定メニュー",
    "settings.ozzy.backendLabel": "バックエンド",
    "settings.ozzy.badUrl": "外部の HTTPS URL を入力してください (HTTP やプライベート IP は利用できません)",
    "settings.ozzy.batchLabel": "1 Slab あたりのチャンク数",
    "settings.ozzy.change": "変更する",
    "settings.ozzy.checking": "接続確認中: {url}/ozzy/v2/status",
    "settings.ozzy.directNote": "デスクトップ版は中継 Worker を使用せず、ロッカーへ直接接続します。",
    "settings.ozzy.engineGatekeeper": "Gatekeeper Worker (直接通信・IP が Worker 側に記録されます)",
    "settings.ozzy.engineLabel": "保存先ストレージ",
    "settings.ozzy.engineOverseas": "海外ロッカー (オニオン回路先の M1 ノードが分散配置)",
    "settings.ozzy.fastChunk": "テスト用小サイズチャンク",
    "settings.ozzy.fastChunkNote": " (64 KiB。無効時は本番仕様の 4 MiB)",
    "settings.ozzy.fetcher": "他ノードの代理でロッカーから取得する (Middle / M1 プロキシ役)",
    "settings.ozzy.fetcherNote": "この役割を有効にすると、取得先ロッカーのログに本端末の IP が記録されます (元のダウンロード要求者の IP は秘匿されます)。無効化しても自身のファイル送受信には影響しません (他ノードが代理取得を担当します)。",
    "settings.ozzy.gkOnly": "登録した Gatekeeper のみを使用する",
    "settings.ozzy.gkTitle": "Gatekeeper Worker の登録 (Tier 1 ストレージ)",
    "settings.ozzy.gkUrlLabel": "Gatekeeper Worker の URL",
    "settings.ozzy.idleLabel": "バッチ待機アイドル時間 (ms)",
    "settings.ozzy.knownWorkers": "P2P で共有された他ノードの Worker: {count} 台",
    "settings.ozzy.liveLockers": "実際の公開ロッカーへアップロード",
    "settings.ozzy.liveLockersNote": " (無効時はインメモリのモックロッカーを使用し、外部通信を行いません)",
    "settings.ozzy.lockersTitle": "ロッカー直接接続",
    "settings.ozzy.maxWaitLabel": "最大待機時間 (ms)",
    "settings.ozzy.noResponse": "応答なし (設定のみ保存しました)",
    "settings.ozzy.ownWorker": "設定中の Worker: <code>{url}</code>",
    "settings.ozzy.register": "登録",
    "settings.ozzy.registerFailed": "登録できませんでした: {reason}",
    "settings.ozzy.registered": "登録しました: {url}",
    "settings.ozzy.responded": "応答あり",
    "settings.ozzy.slabTitle": "Slab バッチ設定",
    "settings.ozzy.storageTitle": "ストレージ設定",
    "settings.ozzy.switchFailed": "切り替えられませんでした: {reason}",
    "settings.ozzy.workerTitle": "中継 Worker",
    "settings.section.connection": "接続",
    "settings.section.guard": "匿名経路",
    "settings.section.hostGuard": "この端末の Guard",
    "settings.section.ozzy": "ファイル共有",
    "settings.section.storage": "データの保管",
    "settings.title": "設定",
    "settings.tracker.clear": "設定を消す",
    "settings.tracker.close": "閉じる",
    "settings.tracker.cloudflare": "Cloudflare Workers (標準)",
    "settings.tracker.current": "現在: ",
    "settings.tracker.deno": "Deno Deploy",
    "settings.tracker.desc": "参加ノード同士が最初にピア発見・接続を行うためのシグナリングサーバーです。公式の中央トラッカーは存在しません。トラッカー運営者には接続元 IP アドレスが観測されます。信頼できる配布元から提供された URL のみを設定してください。",
    "settings.tracker.placeholder": "wss://... または oz-tracker:...",
    "settings.tracker.reset": "設定を消しました",
    "settings.tracker.save": "保存",
    "settings.tracker.saved": "保存しました",
    "settings.tracker.title": "トラッカー",
    "settings.tracker.unset": "未設定 (他のピアを検出できません)",
    "settings.tracker.urlLabel": "トラッカーの URL",
    "sidebar.add": "追加",
    "sidebar.anonymous": "名無し",
    "sidebar.badShare": "共有コードの形式が正しくありません",
    "sidebar.boards": "板",
    "sidebar.cancel": "中止",
    "sidebar.createPrivate": "+ 秘密の板を作る",
    "sidebar.guardLabel": "匿名経路の状態: {label}",
    "sidebar.guardTitle": "{headline} 設定で詳しく見られます。",
    "sidebar.importHint": "受け取った共有コードを貼り付けてください。鍵は暗号化された端末内 DB にのみ保存されます。",
    "sidebar.importLabel": "共有コード",
    "sidebar.join": "共有コードで参加",
    "sidebar.label": "サイドバー",
    "sidebar.lock": "ロック",
    "sidebar.lockTitle": "通信を停止し、パスワード画面に戻ります (データは消えません)",
    "sidebar.nav.about": "仕組みと安全性",
    "sidebar.nav.board": "掲示板",
    "sidebar.nav.settings": "設定",
    "sidebar.nav.status": "状態とログ",
    "sidebar.nav.vault": "ファイル共有",
    "sidebar.navLabel": "画面の切り替え",
    "sidebar.peersTitle": "直接接続中のピア数",
    "sidebar.publicShare": "公開板の共有コードは使えません。公開板は、サイドバーからそのまま開けます",
    "sidebar.status": "状態",
    "sidebar.tracker": "トラッカー",
    "sidebar.trackerMissing": "トラッカー未設定",
    "sidebar.trackerSettings": "トラッカーの設定",
    "sidebar.trackerUnset": "トラッカーが未設定です",
    "sidebar.tripLinked": "⚠ 投稿同士が紐付きます",
    "sidebar.tripNote": "同一トリップを付与した投稿は同一人物のものとして紐付けられます。継続利用時のアクティブ時間帯の相関から発信者を絞り込まれるリスクがあります。",
    "sidebar.wipe": "緊急消去",
    "sidebar.wipeAgain": "もう一度押すと全消去",
    "sidebar.wipeTitle": "通信を止め、この端末のデータをすべて読めなくしてから消去します (元に戻せません)",
    "status.cell.dropped": "捨てた数",
    "status.cell.history": "過去ログ",
    "status.cell.leaseSets": "保持者 (leaseSet)",
    "status.cell.peers": "隣人",
    "status.cell.recent": "直近の投稿",
    "status.cell.relayed": "中継",
    "status.cell.route": "匿名経路",
    "status.cell.service": "受け持ち",
    "status.cell.slots": "保管の枠",
    "status.cell.tracker": "トラッカー",
    "status.eyebrow": "STATUS",
    "status.gridLabel": "状態",
    "status.log.clear": "消す",
    "status.log.copied": "コピーしました",
    "status.log.copy": "コピー",
    "status.log.copyNote": "コピーしたログには、ピア ID の一部などが含まれる場合があります。",
    "status.log.empty": "ログはまだありません",
    "status.log.heavyNote": "細かくするほど処理が重くなります。ロックすると既定に戻ります。",
    "status.log.level.debug": "詳細まで",
    "status.log.level.info": "情報まで",
    "status.log.level.trace": "すべて",
    "status.log.level.warn": "警告まで (既定)",
    "status.log.newRows": "新しい行 {count} 件",
    "status.log.pause": "一時停止",
    "status.log.record": "記録",
    "status.log.recordLabel": "記録の細かさ",
    "status.log.resume": "再開",
    "status.log.rows": "{shown} / {total} 行",
    "status.log.scope": "出どころ",
    "status.log.scopeAll": "すべて",
    "status.log.search": "検索",
    "status.log.searchLabel": "ログを検索",
    "status.log.selectedLabel": "選択行",
    "status.log.warnOnly": "警告以上",
    "status.title": "状態とログ",
    "status.value.dropped": "中継 {relay}・受信の制限 {rate}・握手前 {preVerify}",
    "status.value.history": "取得 {fetches} 回・要求 {attempts} 回",
    "status.value.peers": "{connected} (検証済み {verified}・上限 {max})",
    "status.value.recent": "{posts} 件・{size}",
    "status.value.relayed": "{requests} 件・{size}",
    "status.value.route": "{label} (中継候補 {middles})",
    "status.value.serviceGuard": "Guard 稼働",
    "status.value.serviceNormal": "通常",
    "status.value.trackerConnected": "接続中",
    "status.value.trackerIdle": "待機",
    "storage.close": "閉じる",
    "storage.desc": "他のノードの暗号化データを保管・中継することで、ネットワークが安定します。預かったデータの中身は、あなたにも読めません。",
    "storage.failed": "変更できませんでした",
    "storage.option": "{n} 枠 ({size})",
    "storage.saved": "保存しました",
    "storage.slotsAria": "預かる枠の数",
    "storage.slotsLabel": "預かる枠の数 (1 枠 = {size})",
    "storage.title": "保管の容量",
    "stun.default": " (既定)",
    "stun.desc": "P2P 接続を確立する際に、自身の外部 IP アドレスを識別するためのサーバーです。既定では Google および Cloudflare の公開 STUN を使用します。STUN 運営者には、あなたの IP アドレスと接続時刻が記録されます。独自の STUN サーバーを指定することも可能です。",
    "stun.format": "stun:ホスト名:ポート の形。複数ならカンマで区切ります (4 つまで)。",
    "stun.inUse": "使用中: ",
    "stun.none": "なし (同一ローカルネットワーク内の相手としか接続できません)",
    "stun.placeholder": "stun:ホスト名:3478",
    "stun.reset": "既定に戻しました",
    "stun.resetButton": "既定に戻す",
    "stun.save": "STUN を保存",
    "stun.saved": "保存しました",
    "stun.title": "STUN サーバー",
    "terms.gate.agree": "同意して始める",
    "terms.gate.bodyLabel": "利用規約の本文",
    "terms.gate.check": "利用規約を読み、内容に同意します",
    "terms.gate.decline": "同意しない",
    "terms.gate.declined": "利用規約に同意いただけない場合、OZ はご利用いただけません。このウィンドウ (Web 版ではタブ) を閉じてください。",
    "terms.gate.first": "OZ をご利用いただく前に、以下の利用規約をお読みください。",
    "terms.gate.updated": "利用規約が更新されました。引き続きご利用いただくには、更新後の内容をお読みのうえ、同意してください。",
    "thread.anonymous": "名無しさん {trip}",
    "thread.back": "← 板に戻る",
    "thread.boardLabel": "板: {name}",
    "thread.bytesNotice": "このスレッドは容量の上限 (512KB) に達したので、これ以上書き込めません。新しいスレッドを立ててください。",
    "thread.expiredNotice": "このスレッドは落ちました。最後の書き込みから 30 日、またはスレッドを立ててから 90 日が過ぎると落ちます。",
    "thread.heading": "スレッド: {id}",
    "thread.hidden": "スレッドが埋まった後や落ちた後の書き込み {count} 件は表示していません。",
    "thread.nearBytes": "スレッドの残り容量: 約 {kb} KB",
    "thread.nearPosts": "あと {count} レスで埋まります",
    "thread.newPosts": "新着 {count} 件",
    "thread.overThread": "スレッドの残り容量を超えています",
    "thread.placeholder": ">>レスを入力... (Ctrl+Enterで送信)",
    "thread.postsNotice": "このスレッドは 1000 レスに達したので、これ以上書き込めません。新しいスレッドを立ててください。",
    "thread.quoteTitle": "アンカーを入れる",
    "thread.send": "書き込む",
    "thread.subject": "1 レス",
    "transfer.confirmLeave": "ファイルの送受信が進行中です。離れると転送が中断され、最初からやり直しになります。離れますか?",
    "unlock.badge": "端末内暗号化",
    "unlock.confirm": "パスワード (確認)",
    "unlock.forgot": "パスワードを忘れた場合",
    "unlock.generate": "パスワードを生成",
    "unlock.generateHint": "推測されにくく覚えやすいパスフレーズを自動生成します",
    "unlock.generatedLabel": "作成したパスワード",
    "unlock.mismatch": "確認用のパスワードが一致しません",
    "unlock.noteDown": "このパスワードを、端末の外 (安全な紙など) に控えてください。忘れると復元できません。",
    "unlock.password": "パスワード",
    "unlock.resetAgain": "もう一度押すと、この端末の全データを消去して作り直します (元に戻せません)",
    "unlock.securityTitle": "OZ で守れること・守れないこと",
    "unlock.setupLead": "この端末に保存されるすべてのデータ (投稿履歴・板の鍵など) をこのパスワードで暗号化します。忘れると復元できません。",
    "unlock.setupSubmit": "設定して開始",
    "unlock.setupTitle": "パスワードを設定",
    "unlock.starting": "起動中...",
    "unlock.strength": "強さの目安: {label}",
    "unlock.submit": "解除",
    "unlock.tooShort": "パスワードは {min} 文字以上にしてください",
    "unlock.unlockLead": "この端末のデータは暗号化されています。パスワードを入力してください。",
    "unlock.unlockTitle": "ロックを解除",
    "vault.badLink": "エラー: リンク形式 [[ozzy:v3:...]] が不正です",
    "vault.badRingKey": "メンバー公開鍵の形式が正しくありません: {key}...",
    "vault.badVoucher": "エラー: 無記名招待券 (OZ_VOUCHER) の形式が不正です",
    "vault.chooseDestination": "{name} ({bytes} バイト)。保存先を指定するとダウンロードを開始します",
    "vault.chunksFailed": "チャンクの取得またはハッシュ検証に失敗しました (一時ファイルは破棄されました)",
    "vault.circuitBuilding": "オニオン回路を確立中...",
    "vault.circuitReady": "回路: M1 候補 {count} 台",
    "vault.colFailed": "失敗",
    "vault.colLocker": "ロッカー",
    "vault.colPlaced": "配置完了",
    "vault.copied": "コピーしました",
    "vault.copy": "コピー",
    "vault.deleteFailed": "削除失敗: {reason}",
    "vault.deleteFromLockers": "ロッカーから削除",
    "vault.deleted": "削除完了: {ok}/{total} 個の Slab を削除しました (削除非対応ロッカーの Slab は保管期限まで残存します)。",
    "vault.deletedDone": "削除済み",
    "vault.demoNote": "テストモード: メモリ上のモックロッカーに配置します (外部通信は行いません)",
    "vault.downloadFailed": "ダウンロード失敗: {reason}",
    "vault.dropSub": "またはクリックして選択",
    "vault.dropTitle": "ファイルをドロップ",
    "vault.error": "エラー: {reason}",
    "vault.failure.aborted": "処理を中止しました",
    "vault.failure.badManifest": "Manifest が破損しているか、リンクと整合しません",
    "vault.failure.hashMismatch": "ファイル全体のハッシュ検証に失敗しました (改ざんまたは破損)",
    "vault.failure.insufficientShares": "復元に必要な 16 個のシェアを収集できませんでした (ロッカーのファイル消失・ダウン、または取得役ノードの不足)",
    "vault.failure.noFetchers": "オニオン回路を確立できません (Guard および M1 中継候補ノードの接続待機中)",
    "vault.failure.noManifest": "Manifest を P2P ネットワークから取得できません (保持ノード不在・期限切れ・リンク不正)",
    "vault.fetch": "取得する",
    "vault.fetchingManifestGk": "Gatekeeper Worker から Manifest を取得中...",
    "vault.fetchingManifestP2p": "P2P ストレージから Manifest を取得中...",
    "vault.firstDesc": "参加者各自が Cloudflare Workers に中継用 Worker を 1 台設置して共有し合います。手順と理由は <link>仕組みと安全性</link> に記載されています。",
    "vault.firstTitle": "最初に中継 Worker を設定してください",
    "vault.issuedTitle": "取材源・内部告発者向け招待券トークン",
    "vault.itemSize": "({bytes} バイト / {count} ストライプ)",
    "vault.linkLabel": "共有リンク",
    "vault.linkPlaceholder": "[[ozzy:v3:...]] を貼り付け",
    "vault.madeLinks": "作成した共有リンク",
    "vault.makeMemberKey": "メンバー鍵を生成",
    "vault.manifestFailed": "Manifest を取得できませんでした",
    "vault.manifestGone": "エラー: Manifest を取得できませんでした (削除済みまたは破損)",
    "vault.maxGiB": "許可容量上限 (GiB)",
    "vault.memberKey": "あなたのメンバー公開鍵 (グループ名簿に登録)",
    "vault.mint": "新規招待券 (OZ_VOUCHER) を発行",
    "vault.mintDesc": "アカウントを持たない取材源・告発者に渡す、使い捨ての匿名アップロード許可証です。リング署名によりグループの誰かが発行したことのみが証明され、具体的な発行者は Worker にも特定されません。",
    "vault.mintFailed": "発行できませんでした: {reason}",
    "vault.mintTitle": "招待券を発行する",
    "vault.noCircuit": "エラー: オニオン回路を確立できません (Guard および M1 中継候補の待機中)。直接の外部通信は行いません",
    "vault.pickCancelled": "保存先の選択を取り消しました",
    "vault.placingManifest": "Manifest を P2P ストレージに配置しています...",
    "vault.proxyProgress": "並列プロキシ経由でアップロード中 ({done}/{total} ストライプ完了 | RS({k},{n}) パリティ生成済)",
    "vault.reading": "ファイルを読み込み・ストライプ分割中...",
    "vault.receiveDesc": "共有リンクを入力すると、オニオン回路先の中継ノード群が並列に各ロッカーから分散取得します。",
    "vault.receiveTitle": "ファイルを受信",
    "vault.restored": "復元成功: {name}。下の「端末に保存」で保存してください",
    "vault.restoredBadge": "復元完了",
    "vault.ringLabel": "リング: 名簿の他メンバーの公開鍵 (1 行に 1 つ。多いほど匿名性が高まります。Worker は 8 件以上を要求)",
    "vault.ringPlaceholder": "メンバー公開鍵 (64 文字の hex) を貼り付け",
    "vault.ringTooSmall": "リングメンバーが自分 1 人のみです。Worker に発行元が特定されるのを防ぐため、グループの他メンバーの公開鍵を追加してください",
    "vault.saveAndFetch": "保存先を選択して取得・保存",
    "vault.saveToDevice": "端末に保存",
    "vault.saved": "保存完了: {name} ({bytes} バイト)",
    "vault.sendDescGatekeeper": "Gatekeeper Worker へ直接アップロードします (IP アドレスが Gatekeeper 側に記録されます)。",
    "vault.sendDescOverseas": "暗号化と分割を行い、オニオン回路先の M1 ノード経由で複数の海外ロッカーへ分散配置します。",
    "vault.sendTitle": "ファイルを送信",
    "vault.slabs": "Slab: <strong>{count}</strong> 個 ({lockers})",
    "vault.spreadingDemo": "テストモード: メモリ上のモックロッカーへ Slab を分散配置中...",
    "vault.spreadingLive": "オニオン回路の M1 中継ノードを経由し、公開ロッカー ({lockers}) へ Slab を分散アップロード中...",
    "vault.stepDone": "完了",
    "vault.stepLockers": "ロッカー配置 (Slab {count} 個)",
    "vault.stepManifest": "Manifest 登録",
    "vault.stepRead": "読み込み・暗号化",
    "vault.stepsLabel": "進捗",
    "vault.storageSettings": "保存先の設定",
    "vault.stripePlaced": "ストライプ {done}/{total} の配置が完了しました...",
    "vault.stripesWritten": "ストライプ {done}/{total} を復元して書き出し中...",
    "vault.tabTransfer": "送信・受信",
    "vault.tabVoucher": "招待券",
    "vault.tabsLabel": "ファイル共有",
    "vault.title": "ファイル共有",
    "vault.uploadDone": "完了: {slabs} 個の Slab を {lockers} 社 ({names}) に分散配置し、即時検証を完了しました。Manifest を P2P ストレージに登録しました。",
    "vault.uploadDoneR2": "完了: 全チャンクを 32 台の Gatekeeper へ分散配置し、RAM バッファをゼロクリアしました。",
    "vault.uploadFailed": "アップロード失敗: {reason}",
    "vault.validDays": "有効期間 (日数、最大 14)",
    "vault.voucherLabel": "無記名招待券 (受け取った外部告発者が利用する場合のみ)",
  },
  "en": {
  },
};
