package release

// pinnedSums are known-good SHA-256 checksums of nebula release archives,
// keyed by tag then asset name. Upstream cannot be made to sign its releases,
// so these are the check that does not trust the release's own SHASUM256.txt:
// a pinned version must match here, and upstream's file is then not consulted.
// Add a version with the steps in the README ("Adding a Nebula version").
//
// Source of every entry below: SHASUM256.txt of the slackhq/nebula GitHub
// release of that tag, read on 2026-11-09 with `gh release download <tag>
// -R slackhq/nebula -p SHASUM256.txt` (read-only; nothing downloaded was run).
// Only the archives nebctl can ask for (AssetName) are listed.
var pinnedSums = map[string]map[string]string{
	"v1.12.0": {
		"nebula-darwin.zip":            "fa9c408ec42bfd7391055ab81fb8571d4f27a046aa82481e8dab6230205a049a",
		"nebula-linux-386.tar.gz":      "362ef00fcc5ed33607a89ae5bfe16278e3cf54eae019bee2ff168067b4d0f8c7",
		"nebula-linux-amd64.tar.gz":    "44bf6ae565cf7e5391ca49e8c5f9e3b825755c385eacf79a1f0d28a0b7d3fe51",
		"nebula-linux-arm-5.tar.gz":    "98859388678040bf04c4d4bf0d1fbfc139f86c7281d7ce1b90438431f3bc89c6",
		"nebula-linux-arm-6.tar.gz":    "1d58c5b3d6e8fb6e49df361fd81ac79ee23f0a641d76aaa0abfc85b955355b43",
		"nebula-linux-arm-7.tar.gz":    "776fb7f0a5fc69db9b897bd09f40e46e888a508f1fec4b3c2df9972b3dc7782f",
		"nebula-linux-arm64.tar.gz":    "1279bdde8ccaa0e8c0f90276a295cb471a1d10b5a5308d68d3ed519803df503a",
		"nebula-linux-loong64.tar.gz":  "8dea36405d4bb0af9ce3d4badd6a16ce34ba694ed41bdab16c8bf79344b00b72",
		"nebula-linux-mips.tar.gz":     "09d3a98f8b4c57abb2dc85332ebfb79c002b00b9c1c3c12a5fab944419be8e06",
		"nebula-linux-mipsle.tar.gz":   "1b5fca8a532e2d62c49356cec1bebf28ba6a689d274784f9742e76d99620d495",
		"nebula-linux-mips64.tar.gz":   "9776dae960c7dbcb08320a9e3361d2d2f37b24ffa705fb644e653479ee71772b",
		"nebula-linux-mips64le.tar.gz": "f6315e832b886cf22aa6298a85f4f5875bcda2535bcd32ed700b712df95ca813",
		"nebula-linux-ppc64le.tar.gz":  "c5a09e7e41295e4ee192234dd0aa25b876f6de48401f14681853fac5619bae15",
		"nebula-linux-riscv64.tar.gz":  "5c9cf6e84e409968fbf4de77206b76b397ade1d267c155f06b9f7cff088613b3",
	},
	"v1.11.2": {
		"nebula-darwin.zip":            "ae23ebd29e570d72f28d71e608261d454fb87b1a19b4ca21c2aa26bb4698da88",
		"nebula-linux-386.tar.gz":      "698e40a74d1418bb89d40b12092169362443f75d53b132f5913fce39b0c0e08b",
		"nebula-linux-amd64.tar.gz":    "6140d33f2ec21ce7f6b655b5bc820e93a684d97e51d0ddcf907324b5b28aac1e",
		"nebula-linux-arm-5.tar.gz":    "643120cb40200d9006f8971a2595d1438b249728a2a18dbd883cd127c31daeda",
		"nebula-linux-arm-6.tar.gz":    "d8f86452620eb6ab76bdf9ed9841a309ba8122ac2980c2b7c7e2d1aa8d160e84",
		"nebula-linux-arm-7.tar.gz":    "dc9c890d7ec014ab709e0444592b33f35db4f396f28245c95887844b1565ff41",
		"nebula-linux-arm64.tar.gz":    "85d10e7bc2d121193c1392a1a919172ded7c413f46e602138281cfa9fa1b0231",
		"nebula-linux-loong64.tar.gz":  "fef4136cc22d84f701c05765ffddf69a5e9990cde0f70c5466bf569b24732842",
		"nebula-linux-mips.tar.gz":     "db16b1e34dcde7ff3b4452585b61bd6e65ebbb0cb1a7c5f92f9163e7227eccc3",
		"nebula-linux-mipsle.tar.gz":   "332c402a29f85cd33fc9edf0c3fb1686aea43e2a3a88900936b4dc3136140711",
		"nebula-linux-mips64.tar.gz":   "0a48063bc92e0df7712385413c1219a60432f3dd4b8c2ce93acf1767f457c4b3",
		"nebula-linux-mips64le.tar.gz": "95577e595f972328a8dfecbe7396620c5946898c0a715d25aa5d9184b0685607",
		"nebula-linux-ppc64le.tar.gz":  "f28b602692b0d9427705333b51337697601b7709b80a95c5a2478c48c29ecdd7",
		"nebula-linux-riscv64.tar.gz":  "fff51280d731edd2032497a026cf4baca766556ef55946e82dbf8d68944b1b76",
	},
}
