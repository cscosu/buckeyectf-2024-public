<script lang="ts">
	import { animate, timeline, type AnimationControls } from 'motion';
	import { SvelteToast, toast } from '@zerodevx/svelte-toast';
	import { onMount } from 'svelte';

	type WsResponse =
		| { action: 'sync'; playerHealth: number; bossHealth: number }
		| { action: 'signal' }
		| { action: 'lose'; reason: 'died' | 'timed out' }
		| { action: 'win' }
		| { action: 'flag'; flag: string }
		| { action: 'heal'; amount: number }
		| { action: 'boss_attack'; amount: number }
		| { action: 'player_attack'; amount: number }
		| { action: 'dodged'; amount: number };

	type PlunderResponse =
		| { status: 'success'; amount: number; total: number }
		| { status: 'error'; message: string };

	type DodgeResponse = { status: 'success' } | { status: 'error'; message: string };

	type AttackResponse =
		| { status: 'success'; amount: number }
		| { status: 'error'; message: string };

	let conn: WebSocket;
	if (document.location.protocol === 'https:') {
		conn = new WebSocket('wss://' + document.location.host + '/api/ws');
	} else {
		conn = new WebSocket('ws://' + document.location.host + '/api/ws');
	}

	conn.onmessage = function (evt) {
		const response: WsResponse = JSON.parse(evt.data);

		if (response.action === 'sync') {
			playerHealth = response.playerHealth;
			bossHealth = response.bossHealth;
		} else if (response.action === 'boss_attack') {
			playerHitAnimation.play();
			playerHitAudio.play();
			toast.push(`Took ${response.amount} damage`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
		} else if (response.action === 'dodged') {
			swordMiss.play();
			toast.push(`Dodged attack`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
		} else if (response.action === 'lose') {
			loseAudio.play();
			if (response.reason === 'died') {
				modalTitle = 'You died!';
				modalContent = 'You have been defeated by the boss. Better luck next time!';
				modalOpen = true;
			} else if (response.reason === 'timed out') {
				modalTitle = 'You ran out of time!';
				modalContent = 'The escape wagon has left without you. Better luck next time!';
				modalOpen = true;
			}
		} else if (response.action === 'win') {
			modalTitle = 'You won!';
			modalContent = 'You have defeated the boss. Congratulations!';
			modalOpen = true;
		} else if (response.action === 'flag') {
			modalContent += `Flag: ${response.flag}`;
		} else if (response.action === 'heal') {
			healAudio.play();
			toast.push(`Healed for ${response.amount}`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
		} else if (response.action === 'signal') {
			alertAudio.play();
			toast.push(`Signaled attack`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
		}
	};

	async function attack() {
		const response = await fetch('/api/attack');
		const attack: AttackResponse = await response.json();
		if (attack.status === 'success') {
			swordHit.play();
			bossHitAnimation.play();
			toast.push(`Hit for ${attack.amount}`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
			attacking = true;
			setTimeout(() => {
				attacking = false;
			}, 2000);
		}
	}

	async function dodge() {
		const response = await fetch('/api/dodge');
		const dodge: DodgeResponse = await response.json();
		toast.push(`Dodging...`, {
			dismissable: false,
			theme: {
				'--toastBarHeight': 0
			}
		});
		dodging = true;
		setTimeout(() => {
			dodging = false;
		}, 1000);
	}

	async function plunder() {
		const response = await fetch('/api/plunder');
		const plunder: PlunderResponse = await response.json();
		plunderAudio.play();
		if (plunder.status === 'success') {
			plundered = plunder.total;
			toast.push(`Plundered ${plunder.amount} emeralds`, {
				dismissable: false,
				theme: {
					'--toastBarHeight': 0
				}
			});
		}
		plundering = true;
		setTimeout(() => {
			plundering = false;
		}, 2000);
	}

	const maxPlayerHealth = 100;
	const maxBossHealth = 1000;

	let playerHealth = maxPlayerHealth;
	let bossHealth = maxBossHealth;
	let plundered = 0;

	let bossHitAnimation: AnimationControls;
	let playerHitAnimation: AnimationControls;

	let attacking = false;
	let dodging = false;
	let plundering = false;

	const battle = new Audio('/DojoBattle.mp3');
	const swordHit = new Audio('/sword-hit.wav');
	const swordMiss = new Audio('/sword-miss.wav');
	const plunderAudio = new Audio('/money.wav');
	const healAudio = new Audio('/heal.wav');
	const alertAudio = new Audio('/alert.wav');
	const playerHitAudio = new Audio('/hit.wav');
	const loseAudio = new Audio('/lose.ogg');

	battle.loop = true;
	battle.autoplay = true;
	battle.play();

	let modalOpen = false;
	let modalTitle = '';
	let modalContent = '';

	onMount(() => {
		bossHitAnimation = animate(
			'#boss',
			{ x: [0, -10, 10, 0] },
			{
				duration: 0.5,
				offset: [0, 0.25, 0.75],
				autoplay: false
			}
		);

		playerHitAnimation = animate(
			'#player',
			{ x: [0, -10, 10, 0] },
			{
				duration: 0.5,
				offset: [0, 0.25, 0.75],
				autoplay: false
			}
		);

		document.onclick = () => {
			battle.loop = true;
			battle.play();
		};
	});
</script>

<svelte:head>
	<title>Play</title>
</svelte:head>

<SvelteToast />

{#if modalOpen}
	<div
		class="modal z-50 fixed w-full h-full top-0 left-0 flex items-center justify-center p-8 lg:p-0"
	>
		<div class="modal-overlay fixed w-full h-full bg-gray-900 opacity-50"></div>
		<div
			id="scroll"
			class="w-full bg-cover px-36 py-48 lg:h-max lg:w-1/2 mx-auto rounded-lg shadow-xl z-50 overflow-y-auto"
		>
			<div class="text-2xl font-mono">{modalTitle}</div>
			<div class="p-8 text-2xl font-mono">
				<p class="mb-12">{modalContent}</p>
				<div class="flex justify-around">
					<a href="/">Home</a>
					<a href="/api/new">Play again</a>
				</div>
			</div>
		</div>
	</div>
{/if}

<div class="h-screen flex justify-center">
	<div class="flex flex-col container">
		<div class="grow flex flex-col">
			<div class="grow flex justify-between">
				<div class="grow"></div>
				<div class="flex flex-col justify-end">
					<div>
						<div class="font-mono text-white font-bold">{Math.max(bossHealth, 0)} HP</div>
						<div class="w-[500px] h-1.5 bg-slate-100 rounded-full">
							<div
								class="bg-red-600 h-full rounded-full transition-all"
								style:width="{(Math.max(bossHealth, 0) / maxBossHealth) * 100}%"
							></div>
						</div>
					</div>
					<img src="/gopher.png" alt="boss" id="boss" class="w-[400px]" />
				</div>
			</div>
			<div class="grow flex flex-col justify-between">
				<div>
					<div class="font-mono text-white font-bold">{Math.max(playerHealth, 0)} HP (You)</div>
					<div class="w-96 h-1.5 bg-slate-100 rounded-full">
						<div
							class="bg-red-600 h-full rounded-full transition-all"
							style:width="{(Math.max(playerHealth, 0) / maxPlayerHealth) * 100}%"
						></div>
					</div>
				</div>
				<img src="/dragon.png" alt="player" id="player" class="w-56 mt-8" />
			</div>
		</div>
		<div class="grid grid-flow-col h-1/5 mt-12">
			<button
				on:click={attack}
				class="relative"
				style="cursor: {attacking || dodging ? 'not-allowed' : 'pointer'};"
				disabled={attacking || dodging}
			>
				<div class="absolute w-full h-full flex justify-center items-center font-mono text-2xl">
					Attack
				</div>
				<div
					class="bg-gray-800/15 h-full ease-linear"
					style:width="{attacking ? 0 : 100}%"
					style:transition={attacking ? 'width 2s' : 'none'}
				></div>
			</button>
			<button
				on:click={dodge}
				class="relative"
				style="cursor: {dodging ? 'not-allowed' : 'pointer'};"
				disabled={dodging}
			>
				<div class="absolute w-full h-full flex justify-center items-center font-mono text-2xl">
					Dodge
				</div>
				<div
					class="bg-gray-800/15 h-full ease-linear"
					style:width="{dodging ? 0 : 100}%"
					style:transition={dodging ? 'width 1s' : 'none'}
				></div>
			</button>
			<button
				on:click={plunder}
				class="relative"
				style="cursor: {plundering || dodging ? 'not-allowed' : 'pointer'};"
				disabled={plundering || dodging}
			>
				<div class="absolute w-full h-full flex justify-center items-center font-mono text-2xl">
					Plunder
				</div>
				<div class="absolute w-full bottom-4 font-mono">{plundered} emeralds</div>
				<div
					class="bg-gray-800/15 h-full ease-linear"
					style:width="{plundering ? 0 : 100}%"
					style:transition={plundering ? 'width 2s' : 'none'}
				></div>
			</button>
		</div>
	</div>
</div>

<style>
	#scroll {
		background-image: url('/scroll.png');
	}
</style>
