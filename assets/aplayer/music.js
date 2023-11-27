const music_api = new APlayer({
    element: document.getElementById('player'),
    fixed: true,
    lrcType: 3,
    theme: '#212529',
    order: 'random',
    loop: 'all',
    audio: [{
        name: 'You Are In Love',
	artist: 'Taylor Swift',
        url: '/assets/music/Taylor Swift - You Are In Love.flac',
        lrc: '/assets/music/Taylor Swift - You Are In Love.lrc',
        cover: '/assets/music/Taylor_Switf.png',
    },{
        name: 'Look at the Sky',
	artist: 'Porter Robinson',
        url: 'assets/music/Porter Robinson - Look at the Sky.flac',
        lrc: 'assets/music/Porter Robinson - Look at the Sky.lrc',
        cover: 'assets/music/Porter Robinson - Look at the Sky.png',
    },{
        name: 'speed of youth',
	artist: '牛尾憲輔',
        url: 'assets/music/牛尾憲輔 - speed of youth.flac',
        lrc: 'assets/music/牛尾憲輔 - speed of youth.lrc',
        cover: 'assets/music/牛尾憲輔 - speed of youth.png',
    }

    ]
});
