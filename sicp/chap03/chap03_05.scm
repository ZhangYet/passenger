(define (stream-car stream) (car stream))
(define (stream-cdr stream) (force (cdr stream)))

(define (stream-ref s n)
  (if (= n 0)
      (stream-car s)
      (stream-ref (stream-cdr s) (- n 1))))

(define-syntax cons-stream
  (syntax-rules ()
    ((cons-stream a b)
     (cons a (delay b)))))

(define stream-null? null?)
(define the-empty-stream '())

(define (stream-map proc . argstreams)
  (if (stream-null? (car argstreams))
      the-empty-stream
      (cons-stream
       (apply proc (map stream-car argstreams))
       (apply stream-map (cons proc (map stream-cdr argstreams))))))

(define (stream-for-each proc s)
  (if (stream-null? s)
      'done
      (begin (proc (stream-car s))
	     (stream-for-each proc (stream-cdr s)))))

(define (stream-filter pred stream)
  (cond ((stream-null? stream) the-empty-stream)
	((pred (stream-car stream))
	 (cons-stream (stream-car stream)
		      (stream-filter pred (stream-cdr stream))))
	(else (stream-filter pred (stream-cdr stream)))))

(define (stream-enumerate-interval low high)
  (if (> low high)
      the-empty-stream
      (cons-stream
       low
       (stream-enumerate-interval (+ low 1) high))))

(define (display-line x)
  (newline)
  (display x))

(define (display-stream s)
  (stream-for-each display-line s))

;; (define s (stream-enumerate-interval 1 100))
;; (display-stream s)


;; 3.51
(define (show x)
  (display-line x)
  x)

(define x (stream-map show (stream-enumerate-interval 0 10))) ;; output 0

(stream-ref x 5) ;; output 1-5
(stream-ref x 7) ;; only output 6-7


;; 这正是 3.51 要揭示的核心：
;; - 流的头部是立即求值的——cons-stream 展开成 (cons a (delay b))，a 在构造时就求值，所以定义 x 时 (show 0) 立即执行、打印 0。
;; - 尾部是惰性的——stream-ref x 5 按需逐个 force，因此才依次打印 1~5。
;; - 记忆化——stream-ref x 7 时 0~5 的 promise 已经算过并缓存，force 不再执行 show，只有 6、7 是新算的。
;; 建议注释补一句
;; (define x ...) 打印 0，这样答案才完整。

;; 3.52
(define sum 0)

(define (accum x)
  (set! sum (+ x sum))
  sum)

(define seq (stream-map accum (stream-enumerate-interval 1 20)))
(define y (stream-filter even? seq))
(define z (stream-filter (lambda (x) (= (remainder x 5) 0)) seq))
(stream-ref y 7) ;; output 136
(display-stream z) ;; output 10 15 45 55 105 120 190 210

(display-stream seq)
(display-stream z)

;; sum 210
;; 题目问"如果 delay 不记忆化（按 3.50/3.51 的朴素实现），sum 会是什么"。关键差异：
;; - 记忆化时，y 和 z 共享已算的 seq 项，每个元素只被 accum 一次。
;; - 不记忆化时，force 每次都重跑延迟过程。define z 时 seq 的 2、3 项会被重算（accum 2、accum 3 再执行一遍），所以 sum 会在每一步都偏大，最终不是 210，而是显著更大的值
