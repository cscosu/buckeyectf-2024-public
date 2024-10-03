<svelte:head>
	<title>Home</title>
</svelte:head>

<div class="flex justify-center items-center h-screen">
	<div id="scroll" class="container flex flex-col gap-8 bg-cover px-36 py-48">
		<p class="text-2xl font-mono">Attention, covert operative!</p>
		<p class="text-2xl font-mono">
			This is your top-secret briefing for Operation Emerald Ninja Heist. Your mission, should you
			choose to accept it, involves infiltrating the renowned Dragon’s Breath Dojo under the cover
			of night. Your primary objective is to acquire all emeralds hidden within the dojo’s sacred
			vault. The gems are said to possess unparalleled power, so their retrieval is of utmost
			importance. However, you must remain vigilant: the dojo is protected by a formidable
			guardian—an excessively muscular blue gopher. An encounter with him is inadvisable.
		</p>
		<a class="text-2xl font-mono" href="/api/new">&gt; Enter the Dojo.</a>
	</div>
</div>

<style>
	#scroll {
		background-image: url('/scroll.png');
	}
</style>
