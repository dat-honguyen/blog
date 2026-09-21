---
author: Dat Ho
pubDatetime: 2026-07-30T00:00:00Z
title: 'Tìm kiếm tên gần đúng (fuzzy) trên Postgres: cái gì mới thực sự chịu được lỗi gõ sai'
description: "ILIKE và n-gram index đều trông có vẻ 'fuzzy' nhưng không phải. Phân tích lý do, sự khác biệt của trigram similarity, và query plan thay đổi ra sao khi ta đo thay vì đoán."
tags: [postgresql, databases, performance, indexing, vietnamese]
featured: false
draft: false
---

Một màn hình danh sách có ô lọc theo tên. Người dùng gõ tên bằng tay, nên ô lọc cần chịu được
một chữ cái bị đảo vị trí, bị thiếu, hoặc trường hợp chỉ gõ họ trong khi trường lưu là cả họ
tên. Đây là một yêu cầu rất bình thường, và đáng viết lại chính xác vì những cách sửa "nhìn có
vẻ đúng" cho yêu cầu này lại không làm được điều chúng trông như đang làm.

## Hai thứ trông giống "fuzzy" nhưng không phải

Ô lọc ban đầu là `Contains(term, StringComparison.InvariantCultureIgnoreCase)`, về bản chất là
`ILIKE '%term%'`. Đây là khớp chuỗi con chính xác, liên tục. Chỉ cần sai một ký tự bất kỳ trong
từ khóa là dòng đó không khớp nữa. Không ai gọi đây là "fuzzy" cả, và thực tế cũng không ai gọi,
đây chỉ là điểm khởi đầu ngây thơ.

Lần thử tiếp theo trông có vẻ nghiêm túc hơn. Cơ chế full-text search của Postgres (`tsvector`
và `tsquery`, khớp bằng `@@`, dùng GIN index; xem
[chương full text search trong tài liệu Postgres](https://www.postgresql.org/docs/current/textsearch.html))
có chế độ n-gram: cắt văn bản được index và từ khóa tìm kiếm thành các đoạn 1/2/3 ký tự chồng
lên nhau, rồi khớp nếu mọi n-gram của từ khóa đều xuất hiện trong văn bản. Đây là một kỹ thuật
thực sự hữu ích. Nhưng theo đúng cách nó được xây dựng, kỹ thuật này **không** chịu được lỗi gõ
sai. Nó xử lý đúng trường hợp từ bị cắt ngắn (vì tập n-gram của một tiền tố là tập con của tập
n-gram của từ đầy đủ), nhưng một ký tự bị thay thế sẽ làm thay đổi hẳn tập n-gram, và việc khớp
bị vỡ giống hệt như `ILIKE`. Đây cũng là một phép khớp boolean, có khớp hoặc không, không có
điểm số tương đồng nào để đặt ngưỡng.

Cả hai kỹ thuật này, ở một thời điểm nào đó, từng được tin là "fuzzy search" trong codebase mà
chúng xuất hiện. Không cái nào thực sự là vậy. Khoảng cách giữa những gì một kỹ thuật _được tài
liệu mô tả là làm được_ và những gì người ta _mặc định nó làm được_ mới chính là chủ đề thực sự ở
đây. Sửa nó ít quan trọng hơn việc nhận ra giả định đó chưa từng được kiểm chứng.

## Thứ thực sự tính được độ tương đồng

`pg_trgm` (module trigram của Postgres) là một công cụ khác: nó phân rã văn bản thành các chuỗi
3 ký tự chồng lên nhau, và cho ra một điểm số tương đồng liên tục giữa hai chuỗi, thay vì chỉ
có/không. Module này có hai hàm đáng phân biệt:

- `similarity(a, b)`: đối xứng. Phù hợp khi cả hai vế có độ dài tương đương nhau.
- `word_similarity(a, b)`: so `a` với _chuỗi con khớp tốt nhất_ của `b`, chứ không phải toàn bộ
  `b`. Bất đối xứng, và đây là hàm nên dùng khi từ khóa là một mảnh (ví dụ chỉ có họ) còn văn bản
  đích dài hơn (tên đầy đủ).

Sự khác biệt này không chỉ là hình thức. Thử cả hai hàm với một tên được lưu như
`"Johnathan Vandenberg"`:

| Từ khóa tìm                                        | `similarity()` | `word_similarity()` |
| -------------------------------------------------- | -------------- | ------------------- |
| `Vandenber` (họ bị cắt ngắn)                       | 0.41           | 0.90                |
| `Vandenburg` (sai một ký tự)                       | 0.33           | 0.64                |
| `Jonathan Vandenberg` (thiếu một ký tự, đủ họ tên) | 0.78           | 0.80                |
| `NonExistentPatient123XYZ` (không liên quan)       | 0.00           | 0.00                |

`similarity()` phạt điểm truy vấn dạng mảnh vì phần độ dài nó không bao phủ được, khiến những
tìm kiếm chỉ có họ thực tế bị đẩy xuống gần ngưỡng mà ta có thể chọn cho một kết quả khớp thật.
`word_similarity()` không gặp vấn đề đó, vì nó so với chuỗi con tốt nhất, chứ không phải toàn bộ
chuỗi. Ngưỡng `0.4` vượt qua thoải mái mọi trường hợp lỗi gõ hoặc khớp một phần thực tế ở trên,
trong khi vẫn loại bỏ hoàn toàn một tên không liên quan. Đó là một con số thật, kiểm chứng được,
không phải phỏng đoán, và việc tự suy ra một con số như vậy cho từng tập dữ liệu cụ thể, trước
khi chọn ngưỡng, là điều đáng làm.

## Bài benchmark mới thực sự quan trọng

Tất cả những điều trên sẽ vô nghĩa nếu truy vấn không dùng được index ở quy mô lớn. Đây chính là
chỗ dễ khiến một thứ đúng trong unit test nhưng âm thầm sai khi lên production.

`word_similarity(a, b) > threshold`, khi gọi dưới dạng hàm, không thể được lập kế hoạch như một
điều kiện dùng index. Postgres không có cách nào đẩy một phép so sánh hàm cộng ngưỡng tùy ý vào
một GIN scan, nên nó rơi về quét và tính điểm từng dòng một. Dạng _toán tử_, `a %> b` (so sánh
word-similarity dưới dạng toán tử `pg_trgm` thay vì gọi hàm), mới là thứ mà một GIN index kiểu
`gin_trgm_ops` thực sự tăng tốc được. Cùng một phép so sánh, cùng ngữ nghĩa ngưỡng, chỉ khác cú
pháp, nhưng chính cú pháp đó lại quyết định planner có kế hoạch để dùng hay không.

Sự khác biệt không chỉ là hình thức khi ở quy mô lớn. Với một bảng một triệu dòng dữ liệu tên
tổng hợp thực tế, tìm một lỗi gõ có thật (`"Vandenburg"` khớp với dữ liệu lưu là
`"Vandenberg"`), kết quả:

| Truy vấn                                 | Kế hoạch (plan)              | Thời gian thực thi |
| ---------------------------------------- | ---------------------------- | ------------------ |
| `ILIKE '%term%'`                         | Bitmap Index Scan            | 0.26 ms            |
| Khớp n-gram, không có index n-gram riêng | Seq Scan (gọi hàm từng dòng) | 24.018 ms          |
| `similarity()` dạng hàm                  | Parallel Seq Scan            | 399 ms             |
| `word_similarity()` dạng hàm             | Parallel Seq Scan            | 617 ms             |
| `%>` dạng toán tử                        | Bitmap Index Scan            | 124 ms             |

Có hai điều đáng rút ra từ bảng này. Thứ nhất, toán tử `%>` nhanh hơn khoảng 5 lần so với dạng
hàm của chính cùng một phép so sánh, ở quy mô thực tế. Đây là kiểu khác biệt không bao giờ lộ ra
cho đến khi bạn kiểm thử vượt qua số lượng dòng mà một máy laptop hay database CI thường có. Thứ
hai, khớp n-gram mà không có index n-gram riêng không phải là suy giảm hiệu năng nhẹ nhàng, mà
là một bậc độ lớn hoàn toàn khác: 24 giây trên một triệu dòng, vì phép so sánh n-gram chạy như
một vòng lặp từng dòng, không có gì để planner rút ngắn. Bài học không phải "khớp n-gram tệ." Mà
là kỹ thuật và index giúp kỹ thuật đó khả thi là hai quyết định tách biệt, và bỏ qua quyết định
thứ hai không gây lỗi ồn ào. Nó chỉ âm thầm chậm dần, ở bất kỳ số lượng dòng nào khiến ai đó bắt
đầu để ý.

Còn một điểm ở quy mô nhỏ: ở số lượng dòng cỡ test, planner chọn sequential scan dù index đã tồn
tại và khả dụng, và đó là lựa chọn đúng. Lập kế hoạch dựa trên chi phí (cost-based planning)
nghĩa là index scan không miễn phí, và dưới một số lượng dòng nhất định, seq scan thực sự rẻ hơn.
Index chỉ phát huy tác dụng khi bảng vượt qua ngưỡng chi phí đó, đúng là điểm mà các con số ở trên
bắt đầu tách biệt rõ rệt. Nếu chỉ benchmark với dữ liệu local nhỏ, điều này hoàn toàn vô hình. Nó
chỉ lộ ra khi bạn chủ động kiểm thử ở quy mô mà bạn thực sự kỳ vọng sẽ chạy.

## Rút ra được gì

- "Fuzzy" không phải là một khái niệm được định nghĩa rõ ràng cho một tính năng tìm kiếm. Cần hỏi
  cụ thể nó cần chịu được việc bị cắt ngắn, đảo vị trí, thay thế ký tự, hay cả ba. Mỗi trường hợp
  cần một kỹ thuật khác nhau, và rất dễ triển khai nhầm cái này trong khi yêu cầu thực sự là cái
  khác.
- Tự suy ra ngưỡng tương đồng từ dữ liệu thật cho trường dữ liệu của mình, thay vì tin vào một
  con số lấy từ nơi khác. `similarity()` và `word_similarity()` khác biệt chính xác ở trường hợp
  mà phần lớn tìm kiếm tên thực tế rơi vào: truy vấn một phần so với trường dài hơn.
- Có GIN index không có nghĩa là truy vấn của bạn dùng được nó. Dạng toán tử và dạng gọi hàm của
  cùng một phép so sánh có thể cho ra query plan hoàn toàn khác nhau, hãy kiểm tra bằng
  `EXPLAIN (ANALYZE, BUFFERS)` thay vì mặc định.
- Benchmark ở số lượng dòng bạn kỳ vọng gặp trong production, không phải số lượng dòng đang có
  sẵn trong database dev. Khoảng cách giữa "ổn ở 200 nghìn dòng" và "24 giây ở một triệu dòng"
  không hề báo trước.
